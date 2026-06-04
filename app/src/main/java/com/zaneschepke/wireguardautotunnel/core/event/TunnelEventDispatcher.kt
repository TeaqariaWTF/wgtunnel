package com.zaneschepke.wireguardautotunnel.core.event

import android.content.Context
import com.zaneschepke.tunnel.event.TunnelEvent
import com.zaneschepke.tunnel.model.BackendMode
import com.zaneschepke.tunnel.state.BackendStatus
import com.zaneschepke.wireguardautotunnel.R
import com.zaneschepke.wireguardautotunnel.core.notification.TunnelNotificationLine
import com.zaneschepke.wireguardautotunnel.core.notification.TunnelNotificationService
import com.zaneschepke.wireguardautotunnel.domain.repository.TunnelRepository
import com.zaneschepke.wireguardautotunnel.ui.state.DisplayTunnelState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.launchIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.onEach

class TunnelEventDispatcher(
    private val notificationManager: TunnelNotificationService,
    private val tunnelRepository: TunnelRepository,
    private val context: Context,
) {

    fun bind(
        scope: CoroutineScope,
        providerEvents: Flow<TunnelEvent>,
        providerStatus: StateFlow<BackendStatus>,
        coordinatorErrors: Flow<TunnelErrorEvent>,
        tunnelDisplayStates: StateFlow<Map<Int, DisplayTunnelState>>,
    ) {

        // informational events
        providerEvents
            .distinctUntilChanged()
            .onEach { event ->
                when (event) {
                    is TunnelEvent.FallbackToIpv4 -> {
                        val name = getTunnelName(event.tunnelId)
                        notificationManager.showIpv4Fallback(name)
                    }

                    is TunnelEvent.RecoveredToIpv6 -> {
                        val name = getTunnelName(event.tunnelId)
                        notificationManager.showIpv6Recovery(name)
                    }

                    is TunnelEvent.DynamicDnsUpdate -> {
                        val name = getTunnelName(event.tunnelId)
                        notificationManager.showDynamicDnsUpdate(name)
                    }

                    is TunnelEvent.NoRootShellAccess -> {
                        notificationManager.showRootShellAccess()
                    }
                }
            }
            .launchIn(scope)

        // errors from the coordinator
        coordinatorErrors
            .distinctUntilChanged()
            .onEach { error ->
                when (error) {
                    is TunnelErrorEvent.VpnPermissionDenied -> {
                        notificationManager.showVpnRequired()
                    }

                    is TunnelErrorEvent.InternalFailure -> {
                        notificationManager.showError(error.message)
                    }

                    is TunnelErrorEvent.Socks5PortUnavailable -> {
                        val name = getTunnelName(error.tunnelId)
                        notificationManager.showSocks5PortUnavailable(error.port, name)
                    }

                    is TunnelErrorEvent.HttpPortUnavailable -> {
                        val name = getTunnelName(error.tunnelId)
                        notificationManager.showHttpPortUnavailable(error.port, name)
                    }
                }
            }
            .launchIn(scope)

        // vpn
        combine(
                providerStatus.map { it.activeTunnels },
                tunnelRepository.userTunnelsFlow,
                tunnelDisplayStates,
            ) { activeTunnels, allTunnels, displayStates ->
                activeTunnels
                    .mapNotNull { (id, activeTunnel) ->
                        val mode = activeTunnel.mode ?: return@mapNotNull null
                        if (
                            mode !is BackendMode.Vpn && mode !is BackendMode.Proxy.KillSwitchPrimary
                        ) {
                            return@mapNotNull null
                        }
                        val tunnel = allTunnels.find { it.id == id } ?: return@mapNotNull null

                        val displayState =
                            displayStates[id] ?: DisplayTunnelState.from(activeTunnel)

                        TunnelNotificationLine(
                            id = id,
                            name = tunnel.name,
                            displayState = displayState,
                        )
                    }
                    .associateBy { it.id }
            }
            .distinctUntilChanged()
            .onEach { vpnLines -> notificationManager.updateVpnPersistentNotification(vpnLines) }
            .launchIn(scope)

        // proxy
        combine(
                providerStatus.map { it.activeTunnels },
                tunnelRepository.userTunnelsFlow,
                tunnelDisplayStates,
            ) { activeTunnels, allTunnels, displayStates ->
                activeTunnels
                    .mapNotNull { (id, activeTunnel) ->
                        val mode = activeTunnel.mode ?: return@mapNotNull null
                        if (mode !is BackendMode.Proxy.Standard) return@mapNotNull null

                        val tunnel = allTunnels.find { it.id == id } ?: return@mapNotNull null
                        val displayState =
                            displayStates[id] ?: DisplayTunnelState.from(activeTunnel)

                        TunnelNotificationLine(
                            id = id,
                            name = tunnel.name,
                            displayState = displayState,
                        )
                    }
                    .associateBy { it.id }
            }
            .distinctUntilChanged()
            .onEach { proxyLines ->
                notificationManager.updateProxyPersistentNotification(proxyLines)
            }
            .launchIn(scope)
    }

    private suspend fun getTunnelName(tunnelId: Int): String {
        return tunnelRepository.getById(tunnelId)?.name ?: context.getString(R.string.unknown)
    }
}
