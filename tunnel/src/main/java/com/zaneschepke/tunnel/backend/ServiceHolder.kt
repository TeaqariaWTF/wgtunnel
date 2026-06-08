package com.zaneschepke.tunnel.backend

import android.content.Context
import android.content.Intent
import com.zaneschepke.tunnel.service.TunnelService
import com.zaneschepke.tunnel.service.VpnService
import com.zaneschepke.tunnel.util.BackendException
import java.lang.ref.WeakReference
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import timber.log.Timber

internal class ServiceHolder(val context: Context) {

    internal val uapiPath = context.dataDir.absolutePath

    @Volatile private var vpnService = CompletableDeferred<VpnService>()
    @Volatile private var tunnelService = CompletableDeferred<TunnelService>()
    @Volatile private var vpnServiceDestroyed = CompletableDeferred<Unit>()
    @Volatile private var tunnelServiceDestroyed = CompletableDeferred<Unit>()

    fun set(service: VpnService) {
        vpnService.complete(service)
    }

    fun set(service: TunnelService) {
        tunnelService.complete(service)
    }

    fun signalVpnServiceDestroyed() {
        vpnServiceDestroyed.complete(Unit)
    }

    fun signalTunnelServiceDestroyed() {
        tunnelServiceDestroyed.complete(Unit)
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    suspend fun getVpnService(): VpnService {
        if (vpnService.isCompleted && !vpnService.isCancelled) {
            return vpnService.getCompleted()
        }

        if (android.net.VpnService.prepare(context) != null) {
            throw BackendException.Unauthorized("Permission unavailable to use VpnService")
        }

        context.startForegroundService(Intent(context, VpnService::class.java))

        return try {
            withTimeout(3_000L.milliseconds) { vpnService.await() }
        } catch (e: TimeoutCancellationException) {
            Timber.e(e, "Timed out getting VpnService")
            throw BackendException.InternalError("Failed to get VpnService")
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    suspend fun getTunnelService(): TunnelService {
        if (tunnelService.isCompleted && !tunnelService.isCancelled) {
            return tunnelService.getCompleted()
        }

        context.startForegroundService(Intent(context, TunnelService::class.java))

        return try {
            withTimeout(3_000L.milliseconds) { tunnelService.await() }
        } catch (e: TimeoutCancellationException) {
            Timber.e(e, "Timed out getting TunnelService")
            throw BackendException.InternalError("Failed to get TunnelService")
        }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    suspend fun stopTunnelService() {
        val service =
            if (tunnelService.isCompleted && !tunnelService.isCancelled) {
                tunnelService.getCompleted()
            } else return

        tunnelServiceDestroyed = CompletableDeferred()

        service.shutdown()
        tunnelService = CompletableDeferred()
        withTimeoutOrNull(1_000L.milliseconds) { tunnelServiceDestroyed.await() }
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    suspend fun stopVpnService() {
        val service =
            if (vpnService.isCompleted && !vpnService.isCancelled) {
                vpnService.getCompleted()
            } else return

        vpnServiceDestroyed = CompletableDeferred()

        service.shutdown()
        vpnService = CompletableDeferred()
        withTimeoutOrNull(1_000L.milliseconds) { vpnServiceDestroyed.await() }
    }

    companion object {
        const val DEFAULT_MTU = 1280
        // for consumer to set AOVPN callback
        var alwaysOnCallback: WeakReference<VpnService.AlwaysOnCallback>? = null
    }
}
