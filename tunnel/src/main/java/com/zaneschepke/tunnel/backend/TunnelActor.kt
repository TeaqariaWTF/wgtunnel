package com.zaneschepke.tunnel.backend

import com.zaneschepke.networkmonitor.StableNetworkEngine
import com.zaneschepke.tunnel.DnsConfigManager
import com.zaneschepke.tunnel.Tunnel
import com.zaneschepke.tunnel.event.ActorEvent
import com.zaneschepke.tunnel.event.ActorEvent.ActiveConfigUpdated
import com.zaneschepke.tunnel.event.ActorEvent.BootstrapConfigUpdated
import com.zaneschepke.tunnel.event.ActorEvent.BootstrapStateChanged
import com.zaneschepke.tunnel.event.ActorEvent.EngineStatus
import com.zaneschepke.tunnel.event.ActorEvent.KillSwitchStateChanged
import com.zaneschepke.tunnel.event.ActorEvent.PeersUpdated
import com.zaneschepke.tunnel.event.ActorEvent.ResolvedPeersApplied
import com.zaneschepke.tunnel.event.ActorEvent.TunnelStarted
import com.zaneschepke.tunnel.event.ActorEvent.TunnelStopped
import com.zaneschepke.tunnel.event.TunnelEvent
import com.zaneschepke.tunnel.event.TunnelEvent.NoRootShellAccess
import com.zaneschepke.tunnel.model.BackendMode
import com.zaneschepke.tunnel.model.DnsBootstrapResult
import com.zaneschepke.tunnel.model.PublicKey
import com.zaneschepke.tunnel.model.RunningTunnel
import com.zaneschepke.tunnel.model.TunnelCommand
import com.zaneschepke.tunnel.state.ActiveTunnel
import com.zaneschepke.tunnel.state.ActorState
import com.zaneschepke.tunnel.state.BootstrapState
import com.zaneschepke.tunnel.state.NativeTunnelStatus
import com.zaneschepke.tunnel.state.TunnelRuntimeState
import com.zaneschepke.tunnel.util.RootShellException
import com.zaneschepke.tunnel.util.buildResolvedPeers
import com.zaneschepke.tunnel.util.exponentialBackoffForever
import com.zaneschepke.wireguardautotunnel.parser.ActiveConfig
import kotlin.reflect.KClass
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.mapNotNull
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.supervisorScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import timber.log.Timber

internal class TunnelActor(
    private val scope: CoroutineScope,
    private val engine: TunnelEngine,
    private val stableNetworkEngine: StableNetworkEngine,
) {

    private val inbox = Channel<TunnelCommand>(Channel.UNLIMITED)
    private val stopping = mutableSetOf<Int>()

    // track running hooks to prevent service shutdown until post down hooks complete
    private val _runningPostDownHooks = MutableStateFlow(0)
    val runningHooks = _runningPostDownHooks.asStateFlow()

    private val _state =
        MutableStateFlow(ActorState(byTunnelId = emptyMap(), byHandle = emptyMap()))

    val state: StateFlow<ActorState> = _state.asStateFlow()

    private val _events = MutableSharedFlow<TunnelEvent>(extraBufferCapacity = 32)

    val events = _events.asSharedFlow()

    private val tunnelJobs = mutableMapOf<Int, Job>()

    init {
        scope.launch {
            engine.status.distinctUntilChanged().collect { status ->
                when (status.code) {
                    NativeTunnelStatus.NativeTunnelStatusCode.STOPPED -> {
                        val tunnelId = _state.value.byHandle[status.handle] ?: return@collect
                        stopTunnel(tunnelId, status.handle)
                    }

                    NativeTunnelStatus.NativeTunnelStatusCode.HEALTHY,
                    NativeTunnelStatus.NativeTunnelStatusCode.HANDSHAKE_FAILURE -> {
                        apply(EngineStatus(status))
                    }
                }
            }
        }

        scope.launch {
            for (cmd in inbox) {
                try {
                    when (cmd) {
                        is TunnelCommand.Start -> {
                            if (stopping.contains(cmd.tunnel.id)) {
                                Timber.d(
                                    "Tunnel ${cmd.tunnel.id} is still stopping, ignoring rapid start"
                                )
                                continue
                            }

                            try {
                                val result = engine.start(cmd.tunnel, cmd.mode)
                                stopping -= cmd.tunnel.id
                                apply(TunnelStarted(result, cmd))

                                val runtime = _state.value.byTunnelId[result.tunnelId] ?: continue

                                val job =
                                    startTunnelJobs(
                                        tunnelId = result.tunnelId,
                                        runtime = runtime,
                                        removedPeerEndpoint = result.removedPeerEndpoint,
                                    )

                                tunnelJobs[result.tunnelId] = job

                                job.invokeOnCompletion { tunnelJobs.remove(result.tunnelId, job) }
                            } finally {
                                stopping -= cmd.tunnel.id
                            }
                        }

                        is TunnelCommand.Stop -> {
                            val runtime = _state.value.byTunnelId[cmd.tunnelId] ?: continue
                            stopping += cmd.tunnelId
                            engine.stop(runtime.running.handle, runtime.running.mode)

                            // Extra safety delay for static listen ports to allow OS time to
                            // release port
                            if (runtime.running.mode.config.`interface`.listenPort != null) {
                                delay(250.milliseconds)
                            }
                        }

                        is TunnelCommand.SetBootstrapConfig -> {
                            apply(BootstrapConfigUpdated(cmd.config))
                        }

                        is TunnelCommand.UpdatePeers -> {
                            val runtime = _state.value.byTunnelId[cmd.tunnelId] ?: continue
                            val running = runtime.running

                            val peers = running.buildResolvedPeers(preferIpv6 = cmd.preferIpv6)

                            engine.updatePeers(
                                handle = running.handle,
                                mode = running.mode,
                                peers = peers,
                            )

                            apply(
                                PeersUpdated(
                                    tunnelId = cmd.tunnelId,
                                    peers = peers,
                                    preferIpv6 = cmd.preferIpv6,
                                )
                            )
                        }

                        is TunnelCommand.ApplyResolvedPeers -> {
                            val runtime = _state.value.byTunnelId[cmd.tunnelId] ?: continue
                            val running = runtime.running

                            engine.updatePeers(
                                handle = running.handle,
                                mode = running.mode,
                                peers = cmd.peers,
                            )

                            apply(
                                ResolvedPeersApplied(
                                    tunnelId = cmd.tunnelId,
                                    cache = cmd.cache,
                                    peers = cmd.peers,
                                )
                            )
                        }

                        is TunnelCommand.UpdateActiveConfig -> {
                            val runtime = _state.value.byTunnelId[cmd.tunnelId] ?: continue
                            val running = runtime.running

                            val activeConfig = engine.getActiveConfig(running.handle, running.mode)

                            if (runtime.active.activeConfig == activeConfig) {
                                continue
                            }

                            apply(
                                ActiveConfigUpdated(
                                    tunnelId = cmd.tunnelId,
                                    activeConfig = activeConfig,
                                )
                            )
                        }

                        is TunnelCommand.SetBootstrapState -> {
                            apply(
                                BootstrapStateChanged(
                                    tunnelId = cmd.tunnelId,
                                    bootstrapState = cmd.state,
                                )
                            )
                        }

                        is TunnelCommand.UpdateKillSwitch -> {
                            apply(KillSwitchStateChanged(cmd.enabled))
                        }

                        is TunnelCommand.RunHook -> {
                            val isPostDown = cmd.phase == TunnelCommand.RunHook.Phase.PostDown

                            if (isPostDown) {
                                _runningPostDownHooks.update { it + 1 }
                            }

                            try {
                                cmd.cmds?.forEach { cmd ->
                                    withTimeout(3_000.milliseconds) {
                                        withContext(Dispatchers.IO) { RootShell.run(cmd) }
                                    }
                                }
                            } catch (t: Throwable) {
                                Timber.w(t, "Root shell commands failed")
                                if (t is RootShellException.NoRootAccess) {
                                    _events.emit(NoRootShellAccess(tunnelId = cmd.tunnelId))
                                }
                            } finally {
                                if (isPostDown) {
                                    _runningPostDownHooks.update { (it - 1).coerceAtLeast(0) }
                                }
                            }
                        }
                    }
                } catch (t: Throwable) {
                    Timber.e(t, "Tunnel command failed: $cmd")
                }
            }
        }
    }

    suspend fun send(cmd: TunnelCommand) {
        inbox.send(cmd)
    }

    private fun apply(event: ActorEvent) {
        _state.value = reduce(_state.value, event)
    }

    private fun startTunnelJobs(
        tunnelId: Int,
        runtime: TunnelRuntimeState,
        removedPeerEndpoint: Boolean,
    ): Job {
        return scope.launch {
            supervisorScope {
                val running = runtime.running

                if (!running.mode.config.peers.all { it.isStaticallyConfigured }) {
                    startDnsBootstrapJob(tunnelId)
                }

                if (removedPeerEndpoint) {
                    when (val strategy = running.tunnel.ipStrategy) {
                        Tunnel.IpStrategy.Ipv4Only -> Unit

                        is Tunnel.IpStrategy.PreferIpv6 -> {
                            if (strategy.recoveryEnabled || strategy.fallbackToIpv4Enabled) {
                                startIpv6Job(tunnelId, strategy)
                            }
                        }
                    }
                }

                running.tunnel.features.forEach { feature ->
                    when (feature) {
                        is Tunnel.Feature.ActiveConfigMonitor -> {
                            startActiveConfigJob(tunnelId, feature.intervalSeconds)
                        }

                        Tunnel.Feature.DynamicDNS -> {
                            startDynamicDnsJob(tunnelId)
                        }
                    }
                }

                awaitCancellation()
            }
        }
    }

    private fun stopTunnel(tunnelId: Int, handle: Int) {
        stopping -= tunnelId
        tunnelJobs.remove(tunnelId)?.cancel()
        apply(TunnelStopped(tunnelId, handle))
    }

    private fun CoroutineScope.startDnsBootstrapJob(tunnelId: Int) = launch {
        send(TunnelCommand.SetBootstrapState(tunnelId, BootstrapState.ResolvingDns))

        val runtime = state.value.byTunnelId[tunnelId] ?: return@launch

        val running = runtime.running

        val cache = resolvePeers(running)
        ensureActive()

        val updatedRunning = running.copy(peerBootstrapCache = cache)

        val networkHasIpv6 = stableNetworkEngine.stableState.value?.state?.hasIpv6 ?: false

        val peers =
            updatedRunning.buildResolvedPeers(
                preferIpv6 = running.currentPreferIpv6 && networkHasIpv6
            )
        send(TunnelCommand.SetBootstrapState(tunnelId, BootstrapState.UpdatingPeers))
        send(TunnelCommand.ApplyResolvedPeers(tunnelId = tunnelId, cache = cache, peers = peers))
        send(TunnelCommand.SetBootstrapState(tunnelId, BootstrapState.Complete))
    }

    private fun CoroutineScope.startDynamicDnsJob(tunnelId: Int) = launch {
        val controller =
            DynamicDnsController(
                stabilityWindowMs = DDNS_STABILITY_WINDOW,
                failureWindowMs = DDNS_FAILURE_WINDOW,
                minCheckIntervalMs = DDNS_MIN_CHECK_INTERVAL,
            )

        combine(
                stableNetworkEngine.stableState.filterNotNull(),
                state.mapNotNull { it.byTunnelId[tunnelId]?.active },
            ) { stable, activeTunnel ->
                stable to activeTunnel
            }
            .collect { (stable, activeTunnel) ->
                val runtime = state.value.byTunnelId[tunnelId] ?: return@collect
                if (!stable.state.hasInternet()) return@collect

                val now = System.currentTimeMillis()
                val isHealthy = activeTunnel.transportState is Tunnel.State.Up.Healthy
                val isHandshakeFailure =
                    activeTunnel.transportState is Tunnel.State.Up.HandshakeFailure

                if (!controller.shouldCheck(now, isHealthy, isHandshakeFailure)) return@collect

                // Fresh DNS resolve
                val freshDns = resolvePeers(runtime.running)
                if (freshDns.isEmpty()) {
                    controller.markChecked(now)
                    return@collect
                }

                ensureActive()

                // Query live state from WireGuard UAPI
                val activeConfig =
                    try {
                        engine.getActiveConfig(runtime.running.handle, runtime.running.mode)
                    } catch (t: Throwable) {
                        Timber.w(t, "UAPI query failed during DDNS check")
                        controller.markChecked(now)
                        return@collect
                    }

                val mismatches = findEndpointMismatches(freshDns, activeConfig, runtime.running)
                if (mismatches.isEmpty()) {
                    controller.markChecked(now)
                    return@collect
                }

                controller.markChecked(now)

                Timber.i("Dynamic DNS drift detected for peers: $mismatches — updating")

                _events.emit(
                    TunnelEvent.DynamicDnsUpdate(tunnelId = tunnelId, changedPeers = mismatches)
                )

                val latestRuntime = state.value.byTunnelId[tunnelId] ?: return@collect
                val updatedCache = latestRuntime.running.peerBootstrapCache + freshDns

                send(
                    TunnelCommand.ApplyResolvedPeers(
                        tunnelId = tunnelId,
                        cache = updatedCache,
                        peers =
                            latestRuntime.running
                                .copy(peerBootstrapCache = updatedCache)
                                .buildResolvedPeers(
                                    preferIpv6 = latestRuntime.running.currentPreferIpv6
                                ),
                    )
                )
            }
    }

    private fun findEndpointMismatches(
        freshDns: Map<PublicKey, DnsBootstrapResult>,
        activeConfig: ActiveConfig?,
        running: RunningTunnel,
    ): List<PublicKey> {
        if (activeConfig == null) return emptyList()

        val currentEndpoints = activeConfig.peers.associateBy { it.publicKey }

        return freshDns.mapNotNull { (pubKey, dnsResult) ->
            val current = currentEndpoints[pubKey] ?: return@mapNotNull null
            val currentEndpoint = current.endpoint ?: return@mapNotNull null

            val normalizedCurrent = normalizeEndpointForComparison(currentEndpoint)

            // Choose which fresh address to compare against
            val freshAddress =
                if (running.currentPreferIpv6 && dnsResult.ipv6.isNotEmpty()) {
                    dnsResult.ipv6.first()
                } else {
                    dnsResult.ipv4.firstOrNull() ?: dnsResult.ipv6.firstOrNull()
                } ?: return@mapNotNull null

            if (freshAddress != normalizedCurrent) pubKey else null
        }
    }

    /** Normalizes an endpoint string so IPv6 addresses have brackets. */
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

    private fun CoroutineScope.startIpv6Job(tunnelId: Int, strategy: Tunnel.IpStrategy.PreferIpv6) =
        launch {
            var currentNetworkKey: String? = null
            var hasRecoveredOnThisNetwork = false
            var hasFallenBackOnThisNetwork = false
            var healthySinceMs: Long? = null
            var failureCount = 0
            var firstFailureTime = 0L
            var ipv6Bad = false

            combine(
                    stableNetworkEngine.stableState.filterNotNull(),
                    state.mapNotNull { it.byTunnelId[tunnelId]?.active },
                ) { stable, activeTunnel ->
                    val newKey = stable.key

                    if (newKey != currentNetworkKey) {
                        currentNetworkKey = newKey
                        hasRecoveredOnThisNetwork = false
                        hasFallenBackOnThisNetwork = false
                        healthySinceMs = null
                        failureCount = 0
                        firstFailureTime = 0L
                        ipv6Bad = false

                        Timber.d("Stable network changed resetting IPv6 state ($newKey)")
                    }

                    val now = System.currentTimeMillis()

                    val isUsingIpv6 =
                        activeTunnel.activeConfig?.peers?.any {
                            it.endpoint?.startsWith("[") == true
                        } ?: false

                    val isHealthy = activeTunnel.transportState is Tunnel.State.Up.Healthy
                    val isHandshakeFailure =
                        activeTunnel.transportState is Tunnel.State.Up.HandshakeFailure

                    healthySinceMs = if (isHealthy) healthySinceMs ?: now else null
                    val healthyDuration = healthySinceMs?.let { now - it } ?: 0L

                    Timber.d(
                        "IPv6 strategy | net=$newKey | usingIPv6=$isUsingIpv6 | healthy=$isHealthy | healthyDuration=${healthyDuration}ms | hasRecovered=$hasRecoveredOnThisNetwork | hasFallback=$hasFallenBackOnThisNetwork | hasIPv6=${stable.state.hasIpv6} | ipv6Bad=$ipv6Bad | state=${activeTunnel.transportState}"
                    )

                    if (!isHandshakeFailure) {
                        failureCount = 0
                        firstFailureTime = 0L
                    }

                    // Fallback IPv6 to IPv4
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

                            _events.emit(TunnelEvent.FallbackToIpv4(tunnelId))

                            send(TunnelCommand.UpdatePeers(tunnelId, preferIpv6 = false))
                        }
                    }

                    // Recovery IPv4 to IPv6
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

                            Timber.d(
                                "Recovered to IPv6 on $newKey (healthy for ${healthyDuration}ms)"
                            )

                            _events.emit(TunnelEvent.RecoveredToIpv6(tunnelId))

                            send(TunnelCommand.UpdatePeers(tunnelId, preferIpv6 = true))
                        }
                    }
                }
                .collect {}
        }

    private fun CoroutineScope.startActiveConfigJob(tunnelId: Int, interval: Int) = launch {
        while (isActive) {
            send(TunnelCommand.UpdateActiveConfig(tunnelId))
            delay(interval.seconds)
        }
    }

    private fun reduce(state: ActorState, event: ActorEvent): ActorState {
        return when (event) {
            is EngineStatus -> {
                val tunnelId = state.byHandle[event.status.handle] ?: return state
                val runtime = state.byTunnelId[tunnelId] ?: return state

                val newTransportState =
                    when (event.status.code) {
                        NativeTunnelStatus.NativeTunnelStatusCode.HEALTHY -> Tunnel.State.Up.Healthy

                        NativeTunnelStatus.NativeTunnelStatusCode.HANDSHAKE_FAILURE ->
                            Tunnel.State.Up.HandshakeFailure

                        NativeTunnelStatus.NativeTunnelStatusCode.STOPPED ->
                            return state // should never happen
                    }

                val now = System.currentTimeMillis()

                val updatedActive =
                    runtime.active.copy(
                        transportState = newTransportState,
                        lastStateChangeMs = now,
                        lastHealthChangeMs =
                            if (newTransportState is Tunnel.State.Up.Healthy) {
                                now
                            } else {
                                runtime.active.lastHealthChangeMs
                            },
                    )

                state.copy(
                    byTunnelId =
                        state.byTunnelId + (tunnelId to runtime.copy(active = updatedActive))
                )
            }
            is TunnelStarted -> {
                val result = event.result
                val cmd = event.cmd

                val running =
                    RunningTunnel(
                        handle = result.handle,
                        interfaceName = result.interfaceName,
                        mode = result.mode,
                        tunnel = cmd.tunnel,
                        currentPreferIpv6 = cmd.tunnel.ipStrategy is Tunnel.IpStrategy.PreferIpv6,
                    )

                val runtime =
                    TunnelRuntimeState(
                        running = running,
                        active =
                            ActiveTunnel(
                                transportState = Tunnel.State.Starting,
                                interfaceName = result.interfaceName,
                                mode = result.mode,
                                uptime = System.currentTimeMillis(),
                                activeConfig = null,
                            ),
                    )

                state.copy(
                    byTunnelId = state.byTunnelId + (result.tunnelId to runtime),
                    byHandle = state.byHandle + (result.handle to result.tunnelId),
                )
            }

            is TunnelStopped -> {
                state.copy(
                    byTunnelId = state.byTunnelId - event.tunnelId,
                    byHandle = state.byHandle - event.handle,
                )
            }
            is PeersUpdated -> {
                val runtime = state.byTunnelId[event.tunnelId] ?: return state

                val now = System.currentTimeMillis()

                val updatedActive = runtime.active.copy(lastPeerUpdateMs = now)

                val updatedRunning =
                    runtime.running.copy(
                        currentPreferIpv6 = event.preferIpv6,
                        resolvedPeers = event.peers,
                    )

                state.copy(
                    byTunnelId =
                        state.byTunnelId +
                            (event.tunnelId to
                                runtime.copy(running = updatedRunning, active = updatedActive))
                )
            }
            is ResolvedPeersApplied -> {
                val runtime = state.byTunnelId[event.tunnelId] ?: return state
                val running = runtime.running

                val now = System.currentTimeMillis()

                val updatedActive = runtime.active.copy(lastPeerUpdateMs = now)

                val updatedRunning =
                    running.copy(resolvedPeers = event.peers, peerBootstrapCache = event.cache)

                state.copy(
                    byTunnelId =
                        state.byTunnelId +
                            (event.tunnelId to
                                runtime.copy(running = updatedRunning, active = updatedActive))
                )
            }

            is ActiveConfigUpdated -> {
                val runtime = state.byTunnelId[event.tunnelId] ?: return state

                val updated =
                    runtime.copy(active = runtime.active.copy(activeConfig = event.activeConfig))

                state.copy(byTunnelId = state.byTunnelId + (event.tunnelId to updated))
            }
            is BootstrapStateChanged -> {
                val runtime = state.byTunnelId[event.tunnelId] ?: return state

                val updated =
                    runtime.copy(
                        active = runtime.active.copy(bootstrapState = event.bootstrapState)
                    )

                state.copy(byTunnelId = state.byTunnelId + (event.tunnelId to updated))
            }

            is KillSwitchStateChanged -> {
                state.copy(killSwitchEnabled = event.enabled)
            }

            is BootstrapConfigUpdated -> {
                state.copy(dnsConfig = event.config)
            }
        }
    }

    fun emergencyStop(tunnelId: Int) {
        stopping -= tunnelId
        val runtime = _state.value.byTunnelId[tunnelId] ?: return
        val handle = runtime.running.handle
        val mode = runtime.running.mode

        Timber.d("Emergency stop tunnel $tunnelId (handle=$handle, mode=$mode)")

        engine.stop(handle, mode)

        // Immediately clean up actor state
        stopTunnel(tunnelId, handle)
    }

    // Convenience method for services
    fun emergencyStopAllOfType(modeClass: KClass<out BackendMode>) {
        _state.value.byTunnelId
            .filter { (_, runtime) -> modeClass.isInstance(runtime.running.mode) }
            .keys
            .forEach { emergencyStop(it) }
    }

    suspend fun resolvePeers(runningTunnel: RunningTunnel): Map<PublicKey, DnsBootstrapResult> {

        val peersToResolve = runningTunnel.mode.config.peers.filter { !it.isStaticallyConfigured }

        if (peersToResolve.isEmpty()) return emptyMap()

        val results = mutableMapOf<PublicKey, DnsBootstrapResult>()

        exponentialBackoffForever {
            val bypassNeeded =
                runningTunnel.mode is BackendMode.Vpn || state.value.killSwitchEnabled

            Timber.d("Peer resolution attempt (resolved=${results.size}/${peersToResolve.size})")

            for (peer in peersToResolve) {

                // already resolved
                if (results.containsKey(peer.publicKey)) continue

                val endpoint = peer.endpoint ?: continue
                val host = endpoint.substringBeforeLast(":")

                val dnsConfig = state.value.dnsConfig

                val dnsResult =
                    try {
                        DnsConfigManager.resolveHostBootstrap(
                            host = host,
                            dnsConfig.protocol,
                            dnsConfig.upstream,
                            bypass = bypassNeeded,
                        )
                    } catch (e: Exception) {
                        Timber.w(e, "DNS failed for $host")
                        continue
                    }

                if (dnsResult.ipv4.isEmpty() && dnsResult.ipv6.isEmpty()) {
                    Timber.w("No IPs for $host")
                    continue
                }

                results[peer.publicKey] =
                    dnsResult.copy(
                        ipv4 = dnsResult.ipv4,
                        // normalize
                        ipv6 = dnsResult.ipv6.map { "[$it]" },
                    )

                Timber.d("Resolved $host to ${results[peer.publicKey]}")
            }

            // exit
            if (results.size == peersToResolve.size) {
                return@exponentialBackoffForever
            }

            // force retry
            throw IllegalStateException("Incomplete resolution, retrying...")
        }

        return results
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
