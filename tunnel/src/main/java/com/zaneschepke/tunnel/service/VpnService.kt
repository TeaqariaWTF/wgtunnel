package com.zaneschepke.tunnel.service

import android.content.Intent
import android.os.Build
import android.os.ParcelFileDescriptor
import android.system.OsConstants
import androidx.core.app.ServiceCompat
import com.zaneschepke.hevtunnel.HevTunnelConfig
import com.zaneschepke.hevtunnel.TProxyService
import com.zaneschepke.tunnel.ProxyBackend
import com.zaneschepke.tunnel.Tunnel
import com.zaneschepke.tunnel.backend.Backend
import com.zaneschepke.tunnel.backend.KillSwitch
import com.zaneschepke.tunnel.backend.ServiceHolder
import com.zaneschepke.tunnel.backend.ServiceHolder.Companion.DEFAULT_MTU
import com.zaneschepke.tunnel.backend.ServiceHolder.Companion.alwaysOnCallback
import com.zaneschepke.tunnel.backend.ServiceHolder.Companion.vpnService
import com.zaneschepke.tunnel.backend.SocketProtector
import com.zaneschepke.tunnel.model.BackendMode
import com.zaneschepke.tunnel.model.KillSwitchConfig
import com.zaneschepke.tunnel.util.parseDns
import com.zaneschepke.tunnel.util.parseInetNetwork
import com.zaneschepke.wireguardautotunnel.parser.Config
import java.io.IOException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import org.koin.java.KoinJavaComponent.inject
import timber.log.Timber

class VpnService : android.net.VpnService(), KillSwitch, SocketProtector {

    private val backend: Backend by inject(Backend::class.java)
    private val serviceHolder: ServiceHolder by inject(ServiceHolder::class.java)

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var hevBridgeJob: Job? = null

    @Volatile private var fd: ParcelFileDescriptor? = null

    val builder: Builder
        get() = Builder()

    override fun onCreate() {
        vpnService.complete(this)
        // We call this for all backend modes as it is shared for bootstrapping bypass
        ProxyBackend.setSocketProtector(this)
        serviceHolder.ensureNativeCallbacksRegistered()
        launchForegroundNotification()
        super.onCreate()
    }

    fun launchForegroundNotification() {
        ServiceCompat.startForeground(
            this,
            backend.notificationProvider.vpnNotificationId,
            backend.notificationProvider.vpnInitNotification,
            SYSTEM_EXEMPT_SERVICE_TYPE_ID,
        )
    }

    override fun onDestroy() {
        Timber.d("VpnService destroyed")

        try {
            ProxyBackend.setSocketProtector(null)

            ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)

            disableKillSwitch()
            hevBridgeJob?.cancel()

            serviceScope.cancel()

            backend.emergencyStopAllOfTypeSync(BackendMode.Vpn::class)
            backend.emergencyStopAllOfTypeSync(BackendMode.Proxy.KillSwitchPrimary::class)

            stopHevSocks5Bridge()

            serviceHolder.clear(this)
        } finally {
            super.onDestroy()
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        vpnService.complete(this)
        launchForegroundNotification()

        // Service restarted by system or Always-on VPN started
        if (
            intent == null ||
                intent.component == null ||
                (intent.component!!.packageName != packageName)
        ) {
            Timber.d("VpnService started by system")
            alwaysOnCallback?.get()?.alwaysOnTriggered()
        }
        return START_STICKY
    }

    private fun startHevBridge(port: Int, pass: String): Job {
        val job = serviceScope.launch {
            try {
                val vpnFd = fd ?: throw IOException("No VPN interface fd available")

                repeat(60) { attempt ->
                    try {
                        java.net.Socket().use { socket ->
                            socket.connect(java.net.InetSocketAddress(LOCALHOST, port), 800)
                        }

                        Timber.d(
                            "SOCKS5 proxy is ready on port $port, starting HEV bridge (attempt ${attempt + 1})"
                        )

                        val config =
                            HevTunnelConfig(
                                port = port,
                                mtu = DEFAULT_MTU,
                                ipv4 = IPV4_INTERFACE_ADDRESS,
                                ipv6 = IPV6_INTERFACE_ADDRESS,
                                address = LOCALHOST,
                                username = LOCKDOWN_USERNAME,
                                password = pass,
                            )
                        val hevConfigFile =
                            TProxyService.createHevTunnelConfig(config, this@VpnService.cacheDir)
                        TProxyService.TProxyStartService(hevConfigFile.absolutePath, vpnFd.fd)

                        Timber.d("HEV bridge started successfully - coroutine can now exit")
                        return@launch // safe to exit as hev handles own threading internally
                    } catch (e: Exception) {
                        Timber.w(e, "SOCKS5 connect failed (attempt ${attempt + 1})")
                        if (attempt % 5 == 0) {
                            Timber.d("SOCKS5 not ready yet, retrying...")
                        }
                        delay(300)
                    }
                }
                Timber.e("Timed out waiting for SOCKS5 proxy to be ready")
            } catch (e: Exception) {
                Timber.e(e, "Failed to start HEV bridge")
            }
        }

        // stop HEV when the job is canceled from stopHevSocks5Bridge or onDestroy
        job.invokeOnCompletion { cause ->
            if (cause != null) { // canceled or failed
                Timber.d("HEV bridge job stopped - shutting down native HEV")
                TProxyService.TProxyStopService()
            }
            hevBridgeJob = null
        }

        return job
    }

    private fun disableKillSwitch() {
        fd?.close()
        fd = null
    }

    override fun setKillSwitch(config: KillSwitchConfig?) {
        if (config == null) return disableKillSwitch()
        fd =
            builder
                .apply {
                    setSession(LOCKDOWN_SESSION_NAME)
                    addAddress(IPV4_INTERFACE_ADDRESS, 32)
                    if (config.dualStack) addAddress(IPV6_INTERFACE_ADDRESS, 128)
                    if (config.allowedIps.isEmpty()) {
                        addRoute(IPV4_DEFAULT_ROUTE, 0)
                    } else {
                        config.allowedIps.forEach { net ->
                            Timber.d("Adding allowedIp to kill switch: $net")
                            val (address, prefix) = net.parseInetNetwork()
                            addRoute(address, prefix)
                        }
                    }
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        setMetered(config.metered)
                    }
                    addRoute(IPV6_DEFAULT_ROUTE, 0)
                    setMtu(DEFAULT_MTU)
                    addDnsServer(DEFAULT_DNS_SERVER)

                    // TODO could add an options to kill switch settings for this for ping
                    // sorts/update checks, etc to bypass killswitch
                    // addDisallowedApplication(this@VpnService.packageName)
                }
                .establish()
    }

    fun createTunInterface(tunnel: Tunnel, config: Config): ParcelFileDescriptor? {
        return builder
            .apply {
                setSession(tunnel.name)

                val isSplitTunneling =
                    !config.`interface`.excludedApplications.isNullOrEmpty() ||
                        !config.`interface`.includedApplications.isNullOrEmpty()

                // important for Android Auto in split tunnel scenarios
                // TODO Could make this a standalone feature toggle for strictness as it allows
                // secondary network binding from other apps
                if (isSplitTunneling) allowBypass()

                config.`interface`.includedApplications?.forEach { addAllowedApplication(it) }
                config.`interface`.excludedApplications?.forEach { addDisallowedApplication(it) }

                config.`interface`.address?.split(",")?.forEach { rawAddress ->
                    val (address, prefixLength) = rawAddress.parseInetNetwork()
                    addAddress(address, prefixLength)
                }

                config.`interface`.dns?.let { rawDns ->
                    val dnsConfig = rawDns.parseDns()
                    dnsConfig.dnsServers.forEach { addDnsServer(it) }
                    dnsConfig.searchDomains.forEach { addSearchDomain(it) }
                }

                config.peers.forEach { peer ->
                    peer.allowedIPs?.split(",")?.forEach { entry ->
                        val (address, prefix) = entry.parseInetNetwork()
                        Timber.d("Adding route from config: $address/$prefix")
                        addRoute(address, prefix)
                    }
                }

                allowFamily(OsConstants.AF_INET)
                allowFamily(OsConstants.AF_INET6)

                val mtu = config.`interface`.mtu ?: DEFAULT_MTU
                setMtu(mtu)

                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    setMetered(tunnel.isMetered)
                }

                setUnderlyingNetworks(null)
                setBlocking(true)
            }
            .establish()
    }

    override fun startHevSocks5Bridge(port: Int, pass: String) {
        if (hevBridgeJob != null) return
        hevBridgeJob = startHevBridge(port, pass)
    }

    override fun stopHevSocks5Bridge() {
        hevBridgeJob?.cancel()
        hevBridgeJob = null

        try {
            TProxyService.TProxyStopService()
        } catch (e: Exception) {
            Timber.w(e, "TProxyStopService failed, may already be stopped")
        }
    }

    override fun bypass(fd: Int): Int {
        Timber.d("Bypassing VPN fd: $fd")
        val bypassed =
            try {
                if (protect(fd)) 1 else 0
            } catch (e: Exception) {
                Timber.e(e, "Failed to protect VPN fd")
                0
            }
        Timber.d("Socket protected result: $fd")
        return bypassed
    }

    interface AlwaysOnCallback {
        fun alwaysOnTriggered()
    }

    companion object {
        private const val LOCKDOWN_SESSION_NAME = "Lockdown"
        private const val LOCALHOST = "127.0.0.1"
        private const val IPV4_INTERFACE_ADDRESS = "10.0.0.1"
        private const val IPV6_INTERFACE_ADDRESS = "2001:db8::1"
        const val LOCKDOWN_USERNAME = "local"
        private const val IPV4_DEFAULT_ROUTE = "0.0.0.0"
        private const val IPV6_DEFAULT_ROUTE = "::"
        private const val DEFAULT_DNS_SERVER = "1.1.1.1"

        private const val SYSTEM_EXEMPT_SERVICE_TYPE_ID = 1 shl 10
    }
}
