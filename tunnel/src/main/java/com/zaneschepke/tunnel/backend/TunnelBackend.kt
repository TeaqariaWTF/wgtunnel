package com.zaneschepke.tunnel.backend

import com.zaneschepke.networkmonitor.ActiveNetwork
import com.zaneschepke.networkmonitor.DnsInfo
import com.zaneschepke.networkmonitor.NetworkMonitor
import com.zaneschepke.networkmonitor.PrivateDnsMode
import com.zaneschepke.tunnel.NotificationProvider
import com.zaneschepke.tunnel.ProxyBackend
import com.zaneschepke.tunnel.Tunnel
import com.zaneschepke.tunnel.event.TunnelEvent
import com.zaneschepke.tunnel.model.BackendMode
import com.zaneschepke.tunnel.model.DnsBoostrapConfig
import com.zaneschepke.tunnel.model.DnsBoostrapMode
import com.zaneschepke.tunnel.model.KillSwitchConfig
import com.zaneschepke.tunnel.model.TunnelCommand
import com.zaneschepke.tunnel.service.VpnService
import com.zaneschepke.tunnel.state.BackendStatus
import com.zaneschepke.tunnel.state.KillSwitchState
import com.zaneschepke.tunnel.state.RuntimeDnsConfig
import com.zaneschepke.tunnel.util.BackendException
import java.lang.ref.WeakReference
import kotlin.reflect.KClass
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.distinctUntilChangedBy
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import org.koin.java.KoinJavaComponent.inject
import timber.log.Timber

class TunnelBackend(
    private val scope: CoroutineScope,
    private val networkMonitor: NetworkMonitor,
    override val notificationProvider: NotificationProvider,
) : Backend {

    private val serviceHolder: ServiceHolder by inject(ServiceHolder::class.java)
    private val actor: TunnelActor by inject(TunnelActor::class.java)

    private val _status = MutableStateFlow(BackendStatus())
    override val status: Flow<BackendStatus> = _status.asStateFlow()

    private val _events = MutableSharedFlow<TunnelEvent>(extraBufferCapacity = 32)
    override val events = _events.asSharedFlow()

    private var dnsConfigJob: Job? = null

    init {
        scope.launch {
            var hadVpnTunnels = false
            var hadProxyTunnels = false

            var lastActiveTunnelIds: Set<Int> = emptySet()

            actor.state.collect { actorState ->
                val hasVpnNow =
                    actorState.byTunnelId.values.any { it.running.mode is BackendMode.Vpn }

                val hasProxyNow =
                    actorState.byTunnelId.values.any { it.running.mode is BackendMode.Proxy }

                val activeTunnels = actorState.byTunnelId.mapValues { it.value.active }

                _status.update { current -> current.copy(activeTunnels = activeTunnels) }

                val currentTunnelIds = activeTunnels.keys

                // update tile
                if (currentTunnelIds != lastActiveTunnelIds) {
                    notificationProvider.refreshTile(serviceHolder.context)
                    lastActiveTunnelIds = currentTunnelIds
                }

                // VPN cleanup
                if (hadVpnTunnels && !hasVpnNow) {

                    ensureActive()
                    actor.runningHooks.first { it == 0 }

                    val latestState = actor.state.value
                    val stillHasVpn =
                        latestState.byTunnelId.values.any { it.running.mode is BackendMode.Vpn }

                    if (!shouldKeepVpnServiceAlive(stillHasVpn)) {
                        Timber.d("Stopping VPN service after hooks completed")
                        ProxyBackend.setSocketProtector(null)
                        serviceHolder.stopVpnService()
                    } else {
                        Timber.d("VPN shutdown aborted — state changed during hook wait")
                    }
                }

                // Proxy cleanup
                if (hadProxyTunnels && !hasProxyNow) {

                    ensureActive()
                    actor.runningHooks.first { it == 0 }

                    val latestState = actor.state.value
                    val stillHasProxy =
                        latestState.byTunnelId.values.any { it.running.mode is BackendMode.Proxy }

                    if (!stillHasProxy) {
                        Timber.d("Stopping tunnel service after hooks completed")
                        serviceHolder.stopTunnelService()
                    } else {
                        Timber.d("Proxy shutdown aborted — state changed during hook wait")
                    }
                }

                hadVpnTunnels = hasVpnNow
                hadProxyTunnels = hasProxyNow
            }
        }
    }

    private fun shouldKeepVpnServiceAlive(hasVpnTunnels: Boolean): Boolean {
        return hasVpnTunnels || _status.value.killSwitch.enabled
    }

    override suspend fun start(tunnel: Tunnel, mode: BackendMode): Result<Unit> = runCatching {
        val existing = actor.state.value.byTunnelId[tunnel.id]

        if (existing != null) {
            Timber.d("Tunnel ${tunnel.id} already running — ignoring start")
            return@runCatching
        }

        val scriptsEnabled = tunnel.scriptsEnabled

        val preUp = mode.config.`interface`.preUp
        if (!preUp.isNullOrEmpty() && scriptsEnabled) {
            actor.send(TunnelCommand.RunHook(tunnel.id, TunnelCommand.RunHook.Phase.PreUp, preUp))
        }
        actor.send(TunnelCommand.Start(tunnel, mode))

        val postUp = mode.config.`interface`.postUp
        if (!postUp.isNullOrEmpty() && scriptsEnabled) {
            actor.send(TunnelCommand.RunHook(tunnel.id, TunnelCommand.RunHook.Phase.PostUp, postUp))
        }
    }

    override fun setAlwaysOnCallback(alwaysOnCallback: VpnService.AlwaysOnCallback) {
        ServiceHolder.alwaysOnCallback = WeakReference(alwaysOnCallback)
    }

    override suspend fun stop(id: Int): Result<Unit> = runCatching {
        val runtime =
            actor.state.value.byTunnelId[id]
                ?: throw BackendException.StateConflict(
                    "Tunnel $id is not active or no longer exists"
                )

        val scriptsEnabled = runtime.running.tunnel.scriptsEnabled
        val mode = runtime.running.mode

        val preDown = mode.config.`interface`.preDown
        if (!preDown.isNullOrEmpty() && scriptsEnabled) {
            actor.send(TunnelCommand.RunHook(id, TunnelCommand.RunHook.Phase.PreDown, preDown))
        }
        actor.send(TunnelCommand.Stop(id))

        val postDown = mode.config.`interface`.postDown
        if (!postDown.isNullOrEmpty() && scriptsEnabled) {
            actor.send(TunnelCommand.RunHook(id, TunnelCommand.RunHook.Phase.PostDown, postDown))
        }
    }

    override suspend fun setKillSwitch(config: KillSwitchConfig) = runCatching {
        val service = serviceHolder.getVpnService()
        service.setKillSwitch(config)

        actor.send(TunnelCommand.UpdateKillSwitch(true))

        _status.update { current ->
            current.copy(killSwitch = current.killSwitch.copy(enabled = true, config = config))
        }
    }

    override suspend fun disableKillSwitch() = runCatching {
        val service = serviceHolder.getVpnService()
        service.setKillSwitch(null)

        actor.send(TunnelCommand.UpdateKillSwitch(false))

        _status.update { current ->
            current.copy(
                killSwitch =
                    KillSwitchState(
                        enabled = false,
                        config = null,
                        primaryTunnel = current.killSwitch.primaryTunnel,
                    )
            )
        }
    }

    override suspend fun setBootstrapDnsMode(mode: DnsBoostrapMode) {
        _status.update { it.copy(dnsMode = mode) }

        when (mode) {
            is DnsBoostrapMode.Custom -> {
                Timber.d(
                    "DNS Bootstrap mode set to custom: ${mode.config.protocol} -> ${mode.config.upstream}"
                )

                dnsConfigJob?.cancel()
                dnsConfigJob = null

                actor.send(TunnelCommand.SetBootstrapConfig(RuntimeDnsConfig.from(mode.config)))
            }
            DnsBoostrapMode.System -> {
                Timber.d("DNS Bootstrap mode set to System")
                emitInitialSystemDnsConfig()
                startSystemDnsMonitoring()
            }
        }
    }

    private suspend fun emitInitialSystemDnsConfig() {
        val state =
            withTimeoutOrNull(2_500L) {
                networkMonitor.connectivityStateFlow.first { connectivityState ->
                    val dns = connectivityState.underlyingDnsInfo
                    dns.servers.isNotEmpty() ||
                        connectivityState.activeNetwork is ActiveNetwork.Disconnected
                }
            } ?: networkMonitor.connectivityStateFlow.firstOrNull()

        val dns = state?.underlyingDnsInfo ?: DnsInfo()

        val config = determineSystemDnsBoostrapConfig(dns)

        Timber.d("DNS initial emission: protocol=${config.protocol} upstream=${config.upstream}")

        actor.send(TunnelCommand.SetBootstrapConfig(RuntimeDnsConfig.from(config)))
    }

    override fun emergencyStopAllOfTypeSync(modeClass: KClass<out BackendMode>) {
        actor.emergencyStopAllOfType(modeClass)
        _status.update { it.copy(activeTunnels = emptyMap()) }
        notificationProvider.refreshTile(serviceHolder.context)
    }

    override suspend fun stopAllActiveTunnels(): Result<Unit> = runCatching {
        _status.value.activeTunnels.forEach { (id, _) -> stop(id) }
        _status.update { it.copy(activeTunnels = emptyMap()) }
        notificationProvider.refreshTile(serviceHolder.context)
    }

    private fun determineSystemDnsBoostrapConfig(dnsInfo: DnsInfo): DnsBoostrapConfig {
        return when (dnsInfo.privateDnsMode) {
            PrivateDnsMode.OFF,
            PrivateDnsMode.AUTOMATIC ->
                DnsBoostrapConfig.Plain(
                    dnsInfo.servers.firstOrNull() ?: DnsBoostrapConfig.DEFAULT_PLAIN_UPSTREAM
                )

            PrivateDnsMode.HOSTNAME ->
                dnsInfo.privateDnsHostname
                    ?.takeIf { it.isNotBlank() }
                    ?.let { upstream ->
                        // handle special cases of DoH for private DNS on Android
                        val dohUpstream = DnsBoostrapConfig.SPECIAL_ANDROID_DOH_SERVERS[upstream]
                        if (dohUpstream != null) {
                            DnsBoostrapConfig.DoH(dohUpstream)
                        } else {
                            DnsBoostrapConfig.DoT(upstream)
                        }
                    }
                    ?: DnsBoostrapConfig.Plain(
                        dnsInfo.servers.firstOrNull() ?: DnsBoostrapConfig.DEFAULT_PLAIN_UPSTREAM
                    )
        }
    }

    private fun startSystemDnsMonitoring() {
        if (dnsConfigJob?.isActive == true) return

        dnsConfigJob = scope.launch {
            networkMonitor.connectivityStateFlow
                .distinctUntilChangedBy { it.underlyingDnsInfo }
                .collect { state ->
                    val dns = state.underlyingDnsInfo

                    Timber.d(
                        "PrivateDNS mode=%s hostname=%s",
                        dns.privateDnsMode,
                        dns.privateDnsHostname,
                    )

                    val config = determineSystemDnsBoostrapConfig(dns)

                    actor.send(TunnelCommand.SetBootstrapConfig(RuntimeDnsConfig.from(config)))
                }
        }
    }
}
