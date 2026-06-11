package com.zaneschepke.tunnel.backend

import com.zaneschepke.networkmonitor.ActiveNetwork
import com.zaneschepke.networkmonitor.DnsInfo
import com.zaneschepke.networkmonitor.NetworkMonitor
import com.zaneschepke.networkmonitor.PrivateDnsMode
import com.zaneschepke.networkmonitor.StableNetworkEngine
import com.zaneschepke.tunnel.NotificationProvider
import com.zaneschepke.tunnel.StatusCallback
import com.zaneschepke.tunnel.Tunnel
import com.zaneschepke.tunnel.VpnBackend
import com.zaneschepke.tunnel.backend.dns.AndroidNetworkResolver
import com.zaneschepke.tunnel.backend.dns.CustomDnsResolver
import com.zaneschepke.tunnel.event.TunnelEvent
import com.zaneschepke.tunnel.model.BackendMode
import com.zaneschepke.tunnel.model.DnsBoostrapConfig
import com.zaneschepke.tunnel.model.DnsBoostrapMode
import com.zaneschepke.tunnel.model.DnsBootstrapResult
import com.zaneschepke.tunnel.model.Host
import com.zaneschepke.tunnel.model.KillSwitchConfig
import com.zaneschepke.tunnel.model.PublicKey
import com.zaneschepke.tunnel.service.VpnService
import com.zaneschepke.tunnel.state.ActiveTunnel
import com.zaneschepke.tunnel.state.BackendStatus
import com.zaneschepke.tunnel.state.BootstrapState
import com.zaneschepke.tunnel.state.EngineStartResult
import com.zaneschepke.tunnel.state.KillSwitchState
import com.zaneschepke.tunnel.state.RuntimeDnsConfig
import com.zaneschepke.tunnel.util.RootShellException
import com.zaneschepke.tunnel.util.buildResolvedPeers
import com.zaneschepke.tunnel.util.isLastTunnelOfServiceType
import com.zaneschepke.tunnel.util.toHostMap
import com.zaneschepke.wireguardautotunnel.parser.ActiveConfig
import java.lang.ref.WeakReference
import java.util.concurrent.ConcurrentHashMap
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChangedBy
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.firstOrNull
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import org.koin.java.KoinJavaComponent.inject
import timber.log.Timber

class TunnelBackend(
    private val scope: CoroutineScope,
    private val networkMonitor: NetworkMonitor,
    override val notificationProvider: NotificationProvider,
    private val stableNetworkEngine: StableNetworkEngine,
) : Backend {

    private val serviceHolder: ServiceHolder by inject(ServiceHolder::class.java)
    private val engine: TunnelEngine by inject(TunnelEngine::class.java)

    private val _status = MutableStateFlow(BackendStatus())
    override val status: Flow<BackendStatus> = _status.asStateFlow()

    private val _events = MutableSharedFlow<TunnelEvent>(extraBufferCapacity = 32)
    override val events = _events.asSharedFlow()

    private val tunnelMutex = Mutex()

    private val tunnelJobs = ConcurrentHashMap<Int, Job>()
    private val byHandle = ConcurrentHashMap<Int, Int>()
    private val byTunnelId = ConcurrentHashMap<Int, Int>()
    private val peerUpdateMutexes = ConcurrentHashMap<Int, Mutex>()

    enum class PeerUpdateReason {
        DDNS_CHECK,
        IPV4_FALLBACK,
        IPV6_RECOVERY,
        NETWORK_CHANGE_RESET,
    }

    private var dnsConfigJob: Job? = null

    private val statusCallback = StatusCallback { handle, code ->
        val state = Tunnel.State.fromNative(code)
        state?.let { nativeState ->
            val tunnelId = byHandle[handle] ?: return@let
            updateTunnelTransportState(tunnelId, nativeState)
        }
    }

    override suspend fun start(tunnel: Tunnel, mode: BackendMode): Result<Unit> =
        tunnelMutex.withLock {
            runCatching {
                    if (_status.value.activeTunnels.containsKey(tunnel.id)) {
                        Timber.d("Tunnel ${tunnel.id} already running — ignoring start")
                        return@runCatching
                    }

                    val isFirst = _status.value.activeTunnels.isEmpty()

                    addOrReplaceActiveTunnel(
                        tunnel.id,
                        ActiveTunnel(
                            tunnel = tunnel,
                            transportState = Tunnel.State.Starting,
                            mode = mode,
                        ),
                    )
                    notificationProvider.refreshTile(serviceHolder.context)

                    val scriptsEnabled = tunnel.scriptsEnabled

                    if (isFirst) VpnBackend.setStatusCallback(statusCallback)

                    if (scriptsEnabled)
                        mode.config.`interface`.preUp?.let { runScripts(it, tunnel.id) }

                    val result = engine.start(tunnel, mode)

                    onEngineStartResult(tunnel.id, result)

                    if (scriptsEnabled)
                        mode.config.`interface`.postUp?.let { runScripts(it, tunnel.id) }

                    tunnelJobs[result.tunnelId] =
                        startTunnelJobs(result.handle, tunnel, mode, result.replacedWithNonRoutable)
                }
                .onFailure { cleanup(tunnel.id) }
        }

    private fun onEngineStartResult(tunnelId: Int, result: EngineStartResult) {
        updateActiveTunnel(tunnelId) {
            it.copy(interfaceName = result.interfaceName, uptime = System.currentTimeMillis())
        }
        byHandle[result.handle] = tunnelId
        byTunnelId[tunnelId] = result.handle
    }

    private fun cleanup(tunnelId: Int) {
        tunnelJobs.remove(tunnelId)?.cancel()
        removeActiveTunnel(tunnelId)
        byTunnelId[tunnelId]?.let { byHandle.remove(it) }
        byTunnelId.remove(tunnelId)
        peerUpdateMutexes.remove(tunnelId)
    }

    private suspend fun runScripts(commands: List<String>, tunnelId: Int) {
        try {
            commands.forEach { cmd ->
                withTimeout(3_000.milliseconds) {
                    withContext(Dispatchers.IO) { RootShell.run(cmd) }
                }
            }
        } catch (t: Throwable) {
            Timber.w(t, "Root shell commands failed")
            if (t is RootShellException.NoRootAccess) {
                _events.emit(TunnelEvent.NoRootShellAccess(tunnelId = tunnelId))
            }
        }
    }

    override fun setAlwaysOnCallback(alwaysOnCallback: VpnService.AlwaysOnCallback) {
        ServiceHolder.alwaysOnCallback = WeakReference(alwaysOnCallback)
    }

    override suspend fun stop(id: Int): Result<Unit> = tunnelMutex.withLock {
        runCatching {
            val activeTun = _status.value.activeTunnels[id] ?: return@runCatching
            val mode = activeTun.mode ?: return@runCatching
            updateTunnelTransportState(id, Tunnel.State.Stopping)

            val isLast = _status.value.activeTunnels.size == 1
            val isLastOfServiceType = _status.value.isLastTunnelOfServiceType(id)

            try {
                stopTunnelInternal(id, activeTun)
            } finally {
                notificationProvider.refreshTile(serviceHolder.context)
                if (isLast) VpnBackend.setStatusCallback(null)
                if (isLastOfServiceType) {
                    when (mode) {
                        is BackendMode.Proxy.KillSwitchPrimary,
                        is BackendMode.Vpn -> serviceHolder.stopVpnService()
                        is BackendMode.Proxy.Standard -> serviceHolder.stopTunnelService()
                    }
                }
            }
        }
    }

    private suspend fun stopTunnelInternal(tunnelId: Int, activeTunnel: ActiveTunnel) {
        updateTunnelTransportState(tunnelId, Tunnel.State.Stopping)
        val handle = byTunnelId[tunnelId] ?: return
        val scriptsEnabled = activeTunnel.tunnel?.scriptsEnabled == true
        val mode = activeTunnel.mode ?: return
        try {
            if (scriptsEnabled) mode.config.`interface`.preDown?.let { runScripts(it, tunnelId) }
            engine.stop(handle, activeTunnel.mode)
            if (scriptsEnabled) mode.config.`interface`.postDown?.let { runScripts(it, tunnelId) }
        } finally {
            cleanup(tunnelId)
        }
    }

    override suspend fun setKillSwitch(config: KillSwitchConfig) = runCatching {
        val service = serviceHolder.getVpnService()
        service.setKillSwitch(config)
        _status.update { current ->
            current.copy(killSwitch = current.killSwitch.copy(enabled = true, config = config))
        }
    }

    override suspend fun disableKillSwitch() = runCatching {
        val service = serviceHolder.getVpnService()
        service.setKillSwitch(null)
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
                updateRuntimeDnsConfig(mode.config)
            }
            DnsBoostrapMode.System -> {
                Timber.d("DNS Bootstrap mode set to System")
                emitInitialSystemDnsConfig()
                startSystemDnsMonitoring()
            }
        }
    }

    override suspend fun stopAllActiveTunnels() = tunnelMutex.withLock {
        _status.value.activeTunnels.forEach { (id, tunnel) -> stopTunnelInternal(id, tunnel) }
        notificationProvider.refreshTile(serviceHolder.context)
        VpnBackend.setStatusCallback(null)
        serviceHolder.stopTunnelService()
        serviceHolder.stopVpnService()
        Result.success(Unit)
    }

    private suspend fun emitInitialSystemDnsConfig() {
        val state =
            withTimeoutOrNull(2_500L.milliseconds) {
                networkMonitor.connectivityStateFlow.first { connectivityState ->
                    val dns = connectivityState.underlyingDnsInfo
                    dns.servers.isNotEmpty() ||
                        connectivityState.activeNetwork is ActiveNetwork.Disconnected
                }
            } ?: networkMonitor.connectivityStateFlow.firstOrNull()

        val dns = state?.underlyingDnsInfo ?: DnsInfo()

        val config = determineSystemDnsBoostrapConfig(dns)

        Timber.d("DNS initial emission: protocol=${config.protocol} upstream=${config.upstream}")
        updateRuntimeDnsConfig(config)
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
        dnsConfigJob?.cancel()
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
                    updateRuntimeDnsConfig(config)
                }
        }
    }

    private fun updateStatus(transform: (BackendStatus) -> BackendStatus) {
        _status.update(transform)
    }

    private fun updateRuntimeDnsConfig(boostrapConfig: DnsBoostrapConfig) {
        _status.update { current ->
            current.copy(runtimeDnsConfig = RuntimeDnsConfig.from(boostrapConfig))
        }
    }

    fun addOrReplaceActiveTunnel(id: Int, tunnel: ActiveTunnel) {
        updateStatus { current ->
            current.copy(activeTunnels = current.activeTunnels + (id to tunnel))
        }
    }

    fun updateActiveTunnel(id: Int, transform: (ActiveTunnel) -> ActiveTunnel) {
        updateStatus { current ->
            val existing = current.activeTunnels[id] ?: return@updateStatus current
            current.copy(activeTunnels = current.activeTunnels + (id to transform(existing)))
        }
    }

    fun removeActiveTunnel(id: Int) {
        updateStatus { current -> current.copy(activeTunnels = current.activeTunnels - id) }
    }

    fun updateTunnelTransportState(id: Int, newState: Tunnel.State) {
        updateActiveTunnel(id) { tunnel ->
            val stateChanged = tunnel.transportState != newState
            tunnel.copy(
                transportState = newState,
                lastStateChangeMs =
                    if (stateChanged) {
                        System.currentTimeMillis()
                    } else {
                        tunnel.lastStateChangeMs
                    },
                lastHealthChangeMs =
                    if (newState is Tunnel.State.Up.Healthy) {
                        if (stateChanged || tunnel.lastHealthChangeMs == 0L)
                            System.currentTimeMillis()
                        else tunnel.lastHealthChangeMs
                    } else {
                        tunnel.lastHealthChangeMs
                    },
            )
        }
    }

    fun updateTunnelBootstrapState(id: Int, newState: BootstrapState) {
        updateActiveTunnel(id) { tunnel -> tunnel.copy(bootstrapState = newState) }
    }

    fun markPeerUpdate(id: Int) {
        updateActiveTunnel(id) { tunnel ->
            tunnel.copy(lastPeerUpdateMs = System.currentTimeMillis())
        }
    }

    private fun startTunnelJobs(
        handle: Int,
        tunnel: Tunnel,
        mode: BackendMode,
        replacedWithNonRoutable: Boolean,
    ): Job {
        return scope.launch {
            supervisorScope {
                if (replacedWithNonRoutable) {
                    updateTunnelBootstrapState(tunnel.id, BootstrapState.ResolvingDns)
                    startDnsBootstrapJob(handle, tunnel, mode)
                }

                if (replacedWithNonRoutable) {
                    when (val strategy = tunnel.ipStrategy) {
                        Tunnel.IpStrategy.Ipv4Only -> Unit

                        is Tunnel.IpStrategy.PreferIpv6 -> {
                            if (strategy.recoveryEnabled || strategy.fallbackToIpv4Enabled) {
                                startIpv6Job(handle, tunnel.id, strategy)
                            }
                        }
                    }
                }

                tunnel.features.forEach { feature ->
                    when (feature) {
                        is Tunnel.Feature.ActiveConfigMonitor -> {
                            startActiveConfigJob(handle, tunnel.id, mode, feature.intervalSeconds)
                        }
                        Tunnel.Feature.DynamicDNS -> {
                            startDynamicDnsJob(handle, tunnel.id)
                        }
                    }
                }

                awaitCancellation()
            }
        }
    }

    private fun CoroutineScope.startDnsBootstrapJob(
        handle: Int,
        tunnel: Tunnel,
        mode: BackendMode,
    ) = launch {
        updateTunnelBootstrapState(tunnel.id, BootstrapState.ResolvingDns)
        val resultMap = resolvePeers(mode)
        ensureActive()
        val networkHasIpv6 = stableNetworkEngine.stableState.value?.state?.hasIpv6 ?: false
        val hostMap =
            resultMap.toHostMap(
                preferIpv6 = tunnel.ipStrategy is Tunnel.IpStrategy.PreferIpv6 && networkHasIpv6
            )
        val resolvedPeers = mode.config.buildResolvedPeers(hostMap)
        updateTunnelBootstrapState(tunnel.id, BootstrapState.UpdatingPeers)
        engine.updatePeers(handle, mode, resolvedPeers)
        markPeerUpdate(tunnel.id)
        updateTunnelBootstrapState(tunnel.id, BootstrapState.Complete)
    }

    suspend fun resolvePeers(mode: BackendMode): Map<PublicKey, DnsBootstrapResult> =
        coroutineScope {
            val peersToResolve = mode.config.peers.filter { !it.isStaticallyConfigured }
            if (peersToResolve.isEmpty()) return@coroutineScope emptyMap()

            val results = mutableMapOf<PublicKey, DnsBootstrapResult>()

            stableNetworkEngine.stableState.first { it?.state?.activeNetwork?.network != null }

            var delayMs = 500L

            while (coroutineContext.isActive) {

                val snapshot = stableNetworkEngine.stableState.value?.state
                val network = snapshot?.activeNetwork?.network

                if (network == null) {
                    Timber.d("No network — waiting")
                    delay(delayMs.milliseconds)
                    delayMs = (delayMs * 2).coerceAtMost(30_000)
                    continue
                }

                delayMs = 500L

                val dnsMode = _status.value.dnsMode
                val runtimeDns = _status.value.runtimeDnsConfig
                val bypassNeeded = mode is BackendMode.Vpn || _status.value.killSwitch.enabled

                val resolver =
                    when (dnsMode) {
                        is DnsBoostrapMode.System -> AndroidNetworkResolver(network)
                        is DnsBoostrapMode.Custom -> CustomDnsResolver(runtimeDns, bypassNeeded)
                    }

                var progressed = false

                for (peer in peersToResolve) {

                    if (results.containsKey(peer.publicKey)) continue

                    val host = peer.endpoint?.substringBeforeLast(":") ?: continue

                    try {
                        val dnsResult = resolver.resolve(host)

                        if (dnsResult.ipv4.isNotEmpty() || dnsResult.ipv6.isNotEmpty()) {
                            results[peer.publicKey] =
                                dnsResult.copy(ipv6 = dnsResult.ipv6.map { "[$it]" })
                            progressed = true
                        }
                    } catch (e: Exception) {
                        Timber.w(e, "DNS failed for $host")
                    }
                }

                if (results.keys.containsAll(peersToResolve.map { it.publicKey })) {
                    Timber.d("All peers resolved")
                    return@coroutineScope results
                }

                if (!progressed) {
                    Timber.d("No progress — backing off")
                    delay(delayMs.milliseconds)
                    delayMs = (delayMs * 2).coerceAtMost(30_000)
                }
            }

            return@coroutineScope results
        }

    private fun CoroutineScope.startActiveConfigJob(
        handle: Int,
        tunnelId: Int,
        mode: BackendMode,
        interval: Int,
    ) = launch {
        while (isActive) {
            val activeConfig = engine.getActiveConfig(handle, mode)
            updateActiveTunnel(tunnelId) { it.copy(activeConfig = activeConfig) }
            delay(interval.seconds)
        }
    }

    private fun CoroutineScope.startDynamicDnsJob(handle: Int, tunnelId: Int) = launch {
        val controller =
            DynamicDnsController(
                stabilityWindowMs = DDNS_STABILITY_WINDOW,
                failureWindowMs = DDNS_FAILURE_WINDOW,
                minCheckIntervalMs = DDNS_MIN_CHECK_INTERVAL,
            )

        combine(
                stableNetworkEngine.stableState.filterNotNull(),
                status.mapNotNull { it.activeTunnels[tunnelId] },
            ) { stable, activeTunnel ->
                stable to activeTunnel
            }
            .collect { (stable, activeTunnel) ->
                if (!stable.state.hasInternet()) return@collect

                val now = System.currentTimeMillis()
                val isHealthy = activeTunnel.transportState is Tunnel.State.Up.Healthy
                val isHandshakeFailure =
                    activeTunnel.transportState is Tunnel.State.Up.HandshakeFailure

                if (!controller.shouldCheck(now, isHealthy, isHandshakeFailure)) return@collect

                controller.markChecked(now)

                val mode = activeTunnel.mode ?: return@collect

                reconcilePeers(
                    tunnelId = tunnelId,
                    handle = handle,
                    mode = mode,
                    reason = PeerUpdateReason.DDNS_CHECK,
                )
            }
    }

    private fun findEndpointMismatches(
        freshDns: Map<PublicKey, DnsBootstrapResult>,
        activeConfig: ActiveConfig,
        preferIpv6: Boolean,
    ): Map<PublicKey, Host> {
        val currentEndpoints = activeConfig.peers.associateBy { it.publicKey }

        return freshDns
            .mapNotNull { (pubKey, dnsResult) ->
                val current = currentEndpoints[pubKey] ?: return@mapNotNull null
                val currentEndpoint = current.endpoint ?: return@mapNotNull null

                val normalizedCurrent = normalizeEndpointForComparison(currentEndpoint)

                val freshAddress =
                    if (preferIpv6 && dnsResult.ipv6.isNotEmpty()) {
                        dnsResult.ipv6.first()
                    } else {
                        dnsResult.ipv4.firstOrNull() ?: dnsResult.ipv6.firstOrNull()
                    } ?: return@mapNotNull null

                if (freshAddress != normalizedCurrent) {
                    pubKey to freshAddress
                } else {
                    null
                }
            }
            .toMap()
    }

    private fun normalizeEndpointForComparison(endpoint: String): String {
        val host = endpoint.substringBeforeLast(":")
        val port = endpoint.substringAfterLast(":")

        return if (host.contains(":")) {
            // Looks like IPv6
            if (host.startsWith("[")) endpoint else "[$host]:$port"
        } else {
            endpoint
        }
    }

    private fun CoroutineScope.startIpv6Job(
        handle: Int,
        tunnelId: Int,
        strategy: Tunnel.IpStrategy.PreferIpv6,
    ) = launch {
        var currentNetworkKey: String? = null
        var hasRecoveredOnThisNetwork = false
        var hasFallenBackOnThisNetwork = false
        var healthySinceMs: Long? = null
        var failureCount = 0
        var firstFailureTime = 0L
        var ipv6Bad = false

        combine(
                stableNetworkEngine.stableState.filterNotNull(),
                status.mapNotNull { it.activeTunnels[tunnelId] },
            ) { stable, activeTunnel ->
                stable to activeTunnel
            }
            .collect { (stable, activeTunnel) ->
                val newKey = stable.key
                val mode = activeTunnel.mode ?: return@collect

                // Reset state upon network transition
                if (newKey != currentNetworkKey) {
                    // Capture the old state before we reset local variables
                    val wasFallenBack = activeTunnel.isFallenBackToIpv4ForNetwork

                    currentNetworkKey = newKey
                    hasRecoveredOnThisNetwork = false
                    hasFallenBackOnThisNetwork = false
                    healthySinceMs = null
                    failureCount = 0
                    firstFailureTime = 0L
                    ipv6Bad = false

                    Timber.d("Stable network changed resetting IPv6 state ($newKey)")

                    // Optimistically revert to IPv6 on a new network
                    if (wasFallenBack) {
                        Timber.d(
                            "Network changed while in IPv4 fallback. Attempting optimistic reset."
                        )
                        reconcilePeers(
                            tunnelId = tunnelId,
                            handle = handle,
                            mode = mode,
                            reason = PeerUpdateReason.NETWORK_CHANGE_RESET,
                        )
                    }
                }

                val now = System.currentTimeMillis()

                // Determine if currently using IPv6
                val isUsingIpv6 =
                    activeTunnel.activeConfig?.peers?.any { it.endpoint?.startsWith("[") == true }
                        ?: mode.config.peers.any { it.endpoint?.startsWith("[") == true }

                val isHealthy = activeTunnel.transportState is Tunnel.State.Up.Healthy
                val isHandshakeFailure =
                    activeTunnel.transportState is Tunnel.State.Up.HandshakeFailure

                healthySinceMs = if (isHealthy) healthySinceMs ?: now else null
                val healthyDuration = healthySinceMs?.let { now - it } ?: 0L

                if (!isHandshakeFailure) {
                    failureCount = 0
                    firstFailureTime = 0L
                }

                // Fallback
                if (
                    strategy.fallbackToIpv4Enabled &&
                        isHandshakeFailure &&
                        isUsingIpv6 &&
                        !hasFallenBackOnThisNetwork
                ) {
                    if (failureCount == 0) firstFailureTime = now
                    failureCount++

                    val failureDuration = now - firstFailureTime

                    Timber.d(
                        "IPv6 strategy | Fallback check: failureCount=$failureCount duration=${failureDuration}ms"
                    )

                    if (
                        failureCount >= IPV4_FALLBACK_FAILURE_COUNT &&
                            failureDuration >= IPV4_FALLBACK_FAILURE_DURATION
                    ) {
                        hasFallenBackOnThisNetwork = true
                        ipv6Bad = true

                        Timber.d("Fallback to IPv4 triggered on $newKey (marking IPv6 bad)")

                        reconcilePeers(
                            tunnelId = tunnelId,
                            handle = handle,
                            mode = mode,
                            reason = PeerUpdateReason.IPV4_FALLBACK,
                        )
                    }
                }

                // Recovery
                if (
                    strategy.recoveryEnabled &&
                        !isUsingIpv6 &&
                        !hasRecoveredOnThisNetwork &&
                        healthySinceMs != null &&
                        stable.state.hasIpv6 &&
                        !ipv6Bad
                ) {
                    Timber.d(
                        "IPv6 strategy | Recovery check: healthy for ${healthyDuration}ms (need >= ${RECOVERY_STABILITY_WINDOW}ms)"
                    )

                    if (healthyDuration >= RECOVERY_STABILITY_WINDOW) {
                        hasRecoveredOnThisNetwork = true

                        Timber.d("Recovered to IPv6 on $newKey (healthy for ${healthyDuration}ms)")

                        reconcilePeers(
                            tunnelId = tunnelId,
                            handle = handle,
                            mode = mode,
                            reason = PeerUpdateReason.IPV6_RECOVERY,
                        )
                    }
                }
            }
    }

    private suspend fun reconcilePeers(
        tunnelId: Int,
        handle: Int,
        mode: BackendMode,
        reason: PeerUpdateReason,
    ) {
        val mutex = peerUpdateMutexes.getOrPut(tunnelId) { Mutex() }
        mutex.withLock {
            when (reason) {
                PeerUpdateReason.IPV4_FALLBACK -> {
                    updateActiveTunnel(tunnelId) { it.copy(isFallenBackToIpv4ForNetwork = true) }
                }
                PeerUpdateReason.IPV6_RECOVERY,
                PeerUpdateReason.NETWORK_CHANGE_RESET -> {
                    updateActiveTunnel(tunnelId) { it.copy(isFallenBackToIpv4ForNetwork = false) }
                    if (reason == PeerUpdateReason.NETWORK_CHANGE_RESET) return
                }
                PeerUpdateReason.DDNS_CHECK -> Unit
            }

            val updatedActiveTunnel = _status.value.activeTunnels[tunnelId] ?: return
            val tunnel = updatedActiveTunnel.tunnel ?: return

            val results = resolvePeers(mode)
            if (results.isEmpty()) return

            val networkHasIpv6 = stableNetworkEngine.stableState.value?.state?.hasIpv6 == true
            val preferIpv6 =
                tunnel.ipStrategy is Tunnel.IpStrategy.PreferIpv6 &&
                    networkHasIpv6 &&
                    !updatedActiveTunnel.isFallenBackToIpv4ForNetwork

            val activeConfig =
                try {
                    engine.getActiveConfig(handle, mode)
                } catch (t: Throwable) {
                    Timber.w(t, "UAPI query failed during peer reconciliation")
                    return
                } ?: return

            val mismatches = findEndpointMismatches(results, activeConfig, preferIpv6)

            Timber.d("Reconciliation complete for $reason. Mismatches found: ${mismatches.size}")

            if (mismatches.isNotEmpty()) {
                Timber.i("Updating peers due to $reason: $mismatches")

                val resolvedPeers = mode.config.buildResolvedPeers(mismatches)

                try {
                    engine.updatePeers(handle, mode, resolvedPeers)
                    markPeerUpdate(tunnelId)

                    when (reason) {
                        PeerUpdateReason.IPV4_FALLBACK ->
                            _events.emit(TunnelEvent.FallbackToIpv4(tunnelId))
                        PeerUpdateReason.IPV6_RECOVERY ->
                            _events.emit(TunnelEvent.RecoveredToIpv6(tunnelId))
                        PeerUpdateReason.DDNS_CHECK ->
                            _events.emit(
                                TunnelEvent.DynamicDnsUpdate(tunnelId, mismatches.keys.toList())
                            )
                        PeerUpdateReason.NETWORK_CHANGE_RESET -> Unit
                    }
                } catch (t: Throwable) {
                    Timber.e(t, "Failed to apply peer updates to WireGuard engine")
                }
            } else {
                Timber.d("No mismatches found, skipping event emission.")
            }
        }
    }

    companion object {
        private const val DDNS_MIN_CHECK_INTERVAL = 30_000L
        private const val DDNS_FAILURE_WINDOW = 15_000L
        private const val DDNS_STABILITY_WINDOW = 15_000L
        private const val IPV4_FALLBACK_FAILURE_COUNT = 4
        private const val IPV4_FALLBACK_FAILURE_DURATION = 10_000L
        private const val RECOVERY_STABILITY_WINDOW = 5_000L
    }
}
