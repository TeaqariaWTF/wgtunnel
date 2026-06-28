package com.zaneschepke.tunnel.backend.dns

import android.content.Context
import android.net.DnsResolver
import android.net.Network
import android.os.Build
import android.os.CancellationSignal
import androidx.annotation.RequiresApi
import com.zaneschepke.tunnel.model.DnsBootstrapResult
import java.net.InetAddress
import java.util.concurrent.Executor
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import org.koin.core.component.KoinComponent
import org.koin.core.component.inject
import timber.log.Timber

internal class AndroidNetworkResolver(private val network: Network) : PeerResolver, KoinComponent {
    private val context: Context by inject()

    @Suppress("NewApi")
    private val dnsResolver: DnsResolver by lazy {
        if (Build.VERSION.SDK_INT >= 37) {
            DnsResolver(context, null)
        } else {
            @Suppress("DEPRECATION") DnsResolver.getInstance()
        }
    }

    override suspend fun resolve(host: String): DnsBootstrapResult =
        withContext(Dispatchers.IO) {
            try {
                val ips =
                    withTimeoutOrNull(2_200L.milliseconds) {
                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                            resolveAsync(host)
                        } else {
                            network.getAllByName(host).toList()
                        }
                    }
                        ?: run {
                            Timber.w("DNS resolution timed out after 2200ms for $host")
                            return@withContext DnsBootstrapResult()
                        }

                Timber.d("Resolution from network bind socket: $ips")

                val v4 = ips.filter { it.address.size == 4 }.map { it.hostAddress }
                val v6 = ips.filter { it.address.size == 16 }.map { it.hostAddress }

                DnsBootstrapResult(v4, v6)
            } catch (e: Exception) {
                Timber.e(e, "System DNS failed to resolve host")
                DnsBootstrapResult()
            }
        }

    @RequiresApi(Build.VERSION_CODES.Q)
    private suspend fun resolveAsync(host: String): List<InetAddress> =
        suspendCancellableCoroutine { continuation ->
            val signal = CancellationSignal()
            continuation.invokeOnCancellation { signal.cancel() }

            dnsResolver.query(
                network,
                host,
                DnsResolver.FLAG_EMPTY,
                Executor { it.run() },
                signal,
                object : DnsResolver.Callback<List<InetAddress>> {
                    override fun onAnswer(answer: List<InetAddress>, rcode: Int) {
                        continuation.resume(answer)
                    }

                    override fun onError(error: DnsResolver.DnsException) {
                        continuation.resumeWithException(error)
                    }
                },
            )
        }
}
