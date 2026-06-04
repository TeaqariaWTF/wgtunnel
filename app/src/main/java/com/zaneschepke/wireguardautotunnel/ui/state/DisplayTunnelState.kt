package com.zaneschepke.wireguardautotunnel.ui.state

import android.content.Context
import androidx.annotation.StringRes
import androidx.compose.ui.graphics.Color
import com.zaneschepke.tunnel.Tunnel
import com.zaneschepke.tunnel.model.BackendMode
import com.zaneschepke.tunnel.state.ActiveTunnel
import com.zaneschepke.tunnel.state.BootstrapState
import com.zaneschepke.wireguardautotunnel.R
import com.zaneschepke.wireguardautotunnel.ui.theme.AlertRed
import com.zaneschepke.wireguardautotunnel.ui.theme.CoolGray
import com.zaneschepke.wireguardautotunnel.ui.theme.SilverTree
import com.zaneschepke.wireguardautotunnel.ui.theme.Straw

sealed class DisplayTunnelState {
    data object Disconnected : DisplayTunnelState()

    data object Connecting : DisplayTunnelState()

    data object ResolvingDns : DisplayTunnelState()

    data object EstablishingConnection : DisplayTunnelState()

    data object Ready : DisplayTunnelState()

    data object Connected : DisplayTunnelState()

    data object Degraded : DisplayTunnelState()

    @StringRes
    fun labelRes(): Int {
        return when (this) {
            Disconnected -> R.string.tunnel_state_disconnected
            Connecting -> R.string.tunnel_state_starting
            ResolvingDns -> R.string.tunnel_state_resolving_dns
            EstablishingConnection -> R.string.tunnel_state_establishing_connection
            Ready -> R.string.ready
            Connected -> R.string.tunnel_state_connected
            Degraded -> R.string.tunnel_state_handshake_failure
        }
    }

    fun asLocalizedString(context: Context): String {
        return context.getString(labelRes())
    }

    fun asColor(): Color {
        return when (this) {
            Disconnected -> CoolGray

            Connecting,
            ResolvingDns,
            EstablishingConnection,
            Ready -> Straw

            Connected -> SilverTree

            Degraded -> AlertRed
        }
    }

    companion object {
        fun from(activeTunnel: ActiveTunnel): DisplayTunnelState {
            val transport = activeTunnel.transportState
            val bootstrap = activeTunnel.bootstrapState
            val mode = activeTunnel.mode
            val isVpnStyle = mode is BackendMode.Vpn || mode is BackendMode.Proxy.KillSwitchPrimary

            // Static peers bootstrap never goes to complete, treat none the same
            val bootstrapPhaseDone =
                bootstrap is BootstrapState.Complete || bootstrap is BootstrapState.None

            return when {
                transport is Tunnel.State.Down -> Disconnected

                bootstrap is BootstrapState.Failed -> Degraded

                // DNS resolution still in progress
                bootstrap is BootstrapState.ResolvingDns ||
                    bootstrap is BootstrapState.UpdatingPeers -> ResolvingDns

                transport is Tunnel.State.Up.Healthy -> Connected

                transport is Tunnel.State.Up.HandshakeFailure -> {
                    val age = System.currentTimeMillis() - activeTunnel.lastStateChangeMs

                    if (age > 15_000L && bootstrapPhaseDone) {
                        Degraded
                    } else if (isVpnStyle && bootstrapPhaseDone) {
                        EstablishingConnection
                    } else if (bootstrapPhaseDone) {
                        // For regular proxy mode, we go to ready once past bootstrap phase
                        Ready
                    } else {
                        Connecting
                    }
                }

                transport is Tunnel.State.Starting -> {
                    when {
                        bootstrapPhaseDone -> {
                            if (isVpnStyle) EstablishingConnection else Ready
                        }
                        else -> Connecting
                    }
                }

                // Final fallback after bootstrap phase is done
                bootstrapPhaseDone -> if (isVpnStyle) EstablishingConnection else Ready

                else -> Connecting
            }
        }
    }
}
