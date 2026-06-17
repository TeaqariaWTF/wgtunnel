package com.zaneschepke.tunnel.service

import android.content.Intent
import androidx.core.app.ServiceCompat
import androidx.lifecycle.LifecycleService
import com.zaneschepke.tunnel.backend.Backend
import com.zaneschepke.tunnel.backend.ServiceHolder
import com.zaneschepke.tunnel.backend.ServiceHolder.Companion.alwaysOnCallback
import kotlin.concurrent.atomics.ExperimentalAtomicApi
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import org.koin.java.KoinJavaComponent.inject
import timber.log.Timber

class TunnelService : LifecycleService() {

    private val backend: Backend by inject(Backend::class.java)
    private val serviceHolder: ServiceHolder by inject(ServiceHolder::class.java)
    private val shutdownScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    @Volatile private var userActivatedShutdown = false

    override fun onCreate() {
        serviceHolder.set(this)
        launchForegroundNotification()
        super.onCreate()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        serviceHolder.set(this)
        launchForegroundNotification()

        // Service restarted by system, reuse always-on VPN callback
        if (
            intent == null ||
                intent.component == null ||
                (intent.component!!.packageName != packageName)
        ) {
            Timber.d("TunnelService started by system")
            alwaysOnCallback?.get()?.alwaysOnTriggered()
        }

        return START_STICKY
    }

    @OptIn(ExperimentalAtomicApi::class)
    fun shutdown() {
        userActivatedShutdown = true
        stopSelf()
    }

    @OptIn(ExperimentalAtomicApi::class)
    override fun onDestroy() {
        ServiceCompat.stopForeground(this, ServiceCompat.STOP_FOREGROUND_REMOVE)
        serviceHolder.clearTunnelService()
        if (!userActivatedShutdown) {
            Timber.d("Service being killed by system, clean up tunnels")
            shutdownScope.launch {
                // TODO eventually, this should only shut down proxy mode tunnels with future multi
                // tunnel
                backend.stopAllActiveTunnels()
            }
        }
        super.onDestroy()
    }

    fun launchForegroundNotification() {
        ServiceCompat.startForeground(
            this,
            backend.applicationProvider.proxyNotificationId,
            backend.applicationProvider.proxyInitNotification,
            SPECIAL_USE_SERVICE_TYPE_ID,
        )
    }

    companion object {
        private const val SPECIAL_USE_SERVICE_TYPE_ID = 1 shl 30
    }
}
