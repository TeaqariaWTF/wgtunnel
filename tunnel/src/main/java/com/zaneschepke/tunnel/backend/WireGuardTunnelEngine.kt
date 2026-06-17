package com.zaneschepke.tunnel.backend

import android.net.TrafficStats
import com.zaneschepke.tunnel.ProxyBackend
import com.zaneschepke.tunnel.Tunnel
import com.zaneschepke.tunnel.VpnBackend
import com.zaneschepke.tunnel.model.BackendMode
import com.zaneschepke.tunnel.model.ProxyConfig
import com.zaneschepke.tunnel.service.VpnService
import com.zaneschepke.tunnel.service.VpnService.Companion.HEV_BRIDGE_TRAFFIC_TAG
import com.zaneschepke.tunnel.state.EngineStartResult
import com.zaneschepke.tunnel.util.BackendException
import com.zaneschepke.wireguardautotunnel.parser.ActiveConfig
import com.zaneschepke.wireguardautotunnel.parser.Config
import com.zaneschepke.wireguardautotunnel.parser.PeerSection
import java.io.IOException
import java.net.DatagramSocket
import java.net.ServerSocket
import java.net.SocketException
import java.util.UUID
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.delay

internal class WireGuardTunnelEngine(private val serviceHolder: ServiceHolder) : TunnelEngine {

    override suspend fun start(tunnel: Tunnel, mode: BackendMode): EngineStartResult {

        val ifName = WGT_INTERFACE_PREFIX + tunnel.id

        val (config, replacedWithNonRoutable) = buildConfig(mode)

        // guard against static listenPort issues
        val listenPort = config.`interface`.listenPort
        if (listenPort != null) {
            waitForUdpPortAvailable(listenPort)
        }

        val handle =
            when (mode) {
                is BackendMode.Proxy.KillSwitchPrimary -> {
                    val proxyConfig = buildBridgeProxyConfig()
                    startProxyTunnel(ifName, config, proxyConfig, true)
                }
                is BackendMode.Proxy.Standard -> {
                    val proxyConfig = mode.proxyConfig

                    proxyConfig.socks5?.port?.let { port ->
                        if (!isPortAvailable(port)) {
                            throw BackendException.Socks5PortUnavailable(
                                "SOCKS5 port $port is already in use.",
                                port,
                            )
                        }
                    }

                    proxyConfig.http?.port?.let { port ->
                        if (!isPortAvailable(port)) {
                            throw BackendException.HttpPortUnavailable(
                                "HTTP listener port $port is already in use.",
                                port,
                            )
                        }
                    }
                    startProxyTunnel(ifName, config, proxyConfig, false)
                }
                is BackendMode.Vpn -> {
                    startVpnTunnel(tunnel, ifName, config)
                }
            }

        if (handle < 0) {
            throw BackendException.InternalError("Native start failed: $handle")
        }

        return EngineStartResult(
            tunnelId = tunnel.id,
            handle = handle,
            interfaceName = ifName,
            mode = mode,
            replacedWithNonRoutable = replacedWithNonRoutable,
        )
    }

    private fun isPortAvailable(port: Int): Boolean {
        if (port !in 1..65_535) return false
        return try {
            ServerSocket(port).use { true }
        } catch (_: IOException) {
            false
        }
    }

    private fun buildConfig(mode: BackendMode): Pair<Config, Boolean> {
        var replacedWithNonRoutable = false
        return mode.config.copy(
            peers =
                mode.config.peers.map { peer ->
                    // keep support for valid configs with no endpoints
                    // replace domain configs with nonroutable and let the boostrap job update this
                    // with the real ip later
                    if (!peer.isStaticallyConfigured && peer.endpoint != null) {
                        replacedWithNonRoutable = true
                        val port = peer.endpoint!!.substringAfterLast(":")
                        peer.copy(endpoint = "$TEST_NET_IP:$port", persistentKeepalive = 0)
                    } else peer
                }
        ) to replacedWithNonRoutable
    }

    private fun buildBridgeProxyConfig(): ProxyConfig {
        return ProxyConfig(
            socks5 =
                ProxyConfig.Socks5(
                    port = getAvailablePort(),
                    username = VpnService.LOCKDOWN_USERNAME,
                    password = UUID.randomUUID().toString(),
                )
        )
    }

    override suspend fun updatePeers(handle: Int, mode: BackendMode, peers: List<PeerSection>) {
        val config = mode.config.copy(peers = peers)

        when (mode) {
            is BackendMode.Proxy -> {
                ProxyBackend.awgUpdateProxyTunnelPeers(handle, config.asQuickString())
            }
            is BackendMode.Vpn -> {
                VpnBackend.awgUpdateTunnelPeers(handle, config.asQuickString())
            }
        }
    }

    override suspend fun getActiveConfig(handle: Int, mode: BackendMode): ActiveConfig? {
        val rawConfig =
            when (mode) {
                is BackendMode.Proxy -> ProxyBackend.awgGetProxyConfig(handle)
                is BackendMode.Vpn -> VpnBackend.awgGetConfig(handle)
            }
        return rawConfig?.let { ActiveConfig.parseFromIpc(it) }
    }

    @Throws(IOException::class)
    fun getAvailablePort(): Int {
        TrafficStats.setThreadStatsTag(HEV_BRIDGE_TRAFFIC_TAG)

        try {
            ServerSocket(0).use {
                return it.localPort
            }
        } finally {
            TrafficStats.clearThreadStatsTag()
        }
    }

    override suspend fun stop(handle: Int, mode: BackendMode) {
        when (mode) {
            is BackendMode.Proxy.Standard -> stopProxyTunnel(handle)
            is BackendMode.Vpn -> stopVpnTunnel(handle)
            is BackendMode.Proxy.KillSwitchPrimary -> stopKillSwitchPrimaryTunnel(handle)
        }
    }

    private suspend fun stopKillSwitchPrimaryTunnel(handle: Int) {
        ProxyBackend.awgTurnProxyTunnelOff(handle)
        val service = serviceHolder.getVpnService()
        service.stopHevSocks5Bridge()
    }

    private fun stopProxyTunnel(handle: Int) {
        ProxyBackend.awgTurnProxyTunnelOff(handle)
    }

    private fun stopVpnTunnel(handle: Int) {
        VpnBackend.awgTurnOff(handle)
    }

    private suspend fun startVpnTunnel(tunnel: Tunnel, ifName: String, config: Config): Int {
        val service = ensureVpnProtectorRegistered()

        val fd =
            service.createTunInterface(tunnel, config)?.detachFd()
                ?: throw BackendException.Unauthorized("Failed to create tun interface")

        val handle =
            VpnBackend.awgTurnOn(ifName, fd, config.asQuickString(), serviceHolder.uapiPath)
        if (handle < 0) {
            throw BackendException.InternalError("Internal native error with code: $handle")
        }
        return handle
    }

    private fun isUdpPortAvailable(port: Int): Boolean {
        if (port !in 1..65_535) return false
        return try {
            DatagramSocket(port).use { true }
        } catch (_: SocketException) {
            false
        }
    }

    @Throws(BackendException::class)
    private suspend fun waitForUdpPortAvailable(port: Int, timeoutMs: Long = 3000L) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            if (isUdpPortAvailable(port)) return
            delay(50.milliseconds)
        }
        throw BackendException.ListenPortUnavailable(
            "UDP ListenPort $port is still in use after waiting $timeoutMs ms",
            port,
        )
    }

    private suspend fun startProxyTunnel(
        ifName: String,
        config: Config,
        proxyConfig: ProxyConfig,
        withBridge: Boolean,
    ): Int {
        val quickConfig = buildProxiedQuickString(config, proxyConfig)

        if (!withBridge) {
            serviceHolder.getTunnelService()
        }

        // Get VpnService and ensure protector is registered
        val vpnService =
            if (withBridge) {
                ensureVpnProtectorRegistered()
            } else {
                null
            }

        val handle =
            ProxyBackend.awgStartProxy(
                ifName,
                quickConfig,
                serviceHolder.uapiPath,
                if (withBridge) 1 else 0,
            )
        if (handle < 0) {
            throw BackendException.InternalError("Internal native error")
        }

        // Start HEV bridge after the proxy tunnel is up
        if (withBridge && vpnService != null) {
            val port =
                proxyConfig.socks5?.port
                    ?: throw BackendException.InternalError(
                        "Bridge port not set for kill switch proxy config"
                    )
            val pass =
                proxyConfig.socks5.password
                    ?: throw BackendException.InternalError(
                        "Bridge pass not set for kill switch proxy config"
                    )

            vpnService.startHevSocks5Bridge(port, pass)
        }

        return handle
    }

    /**
     * Gets the VpnService and starts if needed while ensuring the protector is registered. This is
     * needed before any native call that uses NewStdNetBindWithControl.
     */
    private suspend fun ensureVpnProtectorRegistered(): VpnService {
        val service = serviceHolder.getVpnService()
        ProxyBackend.setSocketProtector(service)
        return service
    }

    private fun buildProxiedQuickString(config: Config, proxyConfig: ProxyConfig): String {
        return buildString {
            append(config.asQuickString())
            append(System.lineSeparator())
            append(proxyConfig.toQuickString())
        }
    }

    companion object {
        const val TEST_NET_IP = "192.0.2.1"
        const val WGT_INTERFACE_PREFIX = "wgtun"
    }
}
