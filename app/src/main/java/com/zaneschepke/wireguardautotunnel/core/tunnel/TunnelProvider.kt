package com.zaneschepke.wireguardautotunnel.core.tunnel

import com.zaneschepke.wireguardautotunnel.domain.enums.BackendError
import com.zaneschepke.wireguardautotunnel.domain.enums.BackendState
import com.zaneschepke.wireguardautotunnel.domain.enums.TunnelStatus
import com.zaneschepke.wireguardautotunnel.domain.model.TunnelConf
import com.zaneschepke.wireguardautotunnel.domain.state.TunnelState
import com.zaneschepke.wireguardautotunnel.domain.state.TunnelStatistics
import java.util.concurrent.ConcurrentHashMap
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow

interface TunnelProvider {
    /** Starts the specified tunnel configuration. */
    suspend fun startTunnel(tunnelConf: TunnelConf)

    /**
     * Stops the specified tunnel, or all tunnels if none is provided.
     *
     * @param tunnelConf The tunnel to stop, or null to stop all active tunnels.
     * @param reason The reason for stopping, defaults to USER for manual stops. Callers should
     *   override with specific reasons (e.g., PING, CONFIG_CHANGED) when applicable.
     */
    suspend fun stopTunnel(
        tunnelConf: TunnelConf? = null,
        reason: TunnelStatus.StopReason = TunnelStatus.StopReason.USER,
    )

    /**
     * Bounces (stops and restarts) the specified tunnel.
     *
     * @param tunnelConf The tunnel to bounce.
     * @param reason The reason for bouncing, defaults to USER for manual actions. Callers should
     *   override with specific reasons (e.g., PING, CONFIG_CHANGED) when applicable.
     */
    suspend fun bounceTunnel(
        tunnelConf: TunnelConf,
        reason: TunnelStatus.StopReason = TunnelStatus.StopReason.USER,
    )

    fun setBackendState(backendState: BackendState, allowedIps: Collection<String>)

    fun getBackendState(): BackendState

    suspend fun runningTunnelNames(): Set<String>

    fun getStatistics(tunnelConf: TunnelConf): TunnelStatistics?

    val activeTunnels: StateFlow<Map<TunnelConf, TunnelState>>

    val errorEvents: SharedFlow<Pair<TunnelConf, BackendError>>

    val bouncingTunnelIds: ConcurrentHashMap<Int, TunnelStatus.StopReason>

    fun hasVpnPermission(): Boolean

    suspend fun updateTunnelStatistics(tunnel: TunnelConf)
}
