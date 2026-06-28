package com.zaneschepke.networkmonitor

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.database.ContentObserver
import android.location.LocationManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.wifi.WifiManager
import android.os.Build
import android.provider.Settings
import com.zaneschepke.networkmonitor.AndroidNetworkMonitor.WifiDetectionMethod.DEFAULT
import com.zaneschepke.networkmonitor.AndroidNetworkMonitor.WifiDetectionMethod.LEGACY
import com.zaneschepke.networkmonitor.AndroidNetworkMonitor.WifiDetectionMethod.ROOT
import com.zaneschepke.networkmonitor.AndroidNetworkMonitor.WifiDetectionMethod.SHIZUKU
import com.zaneschepke.networkmonitor.shizuku.ShizukuShell
import com.zaneschepke.networkmonitor.util.getLegacySecurityType
import com.zaneschepke.networkmonitor.util.getWifiSecurityType
import com.zaneschepke.networkmonitor.util.getWifiSsid
import com.zaneschepke.networkmonitor.util.hasRequiredLocationPermissions
import com.zaneschepke.networkmonitor.util.isAirplaneModeOn
import com.zaneschepke.networkmonitor.util.isLocationServicesEnabled
import java.net.Inet6Address
import kotlin.time.Duration.Companion.milliseconds
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.FlowPreview
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.debounce
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.shareIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import timber.log.Timber

class AndroidNetworkMonitor(
    private val appContext: Context,
    private val configurationListener: ConfigurationListener,
    private val applicationScope: CoroutineScope,
) : NetworkMonitor {

    private val actionPermissionCheck = "${appContext.packageName}.PERMISSION_CHECK"

    interface ConfigurationListener {
        val detectionMethod: Flow<WifiDetectionMethod>

        // maybe this shouldn't just be a string result
        suspend fun runRootShellCommand(cmd: String): String?
    }

    companion object {
        const val LOCATION_SERVICES_FILTER: String = "android.location.PROVIDERS_CHANGED"
        const val ANDROID_UNKNOWN_SSID: String = "<unknown ssid>"
        const val WIFI_SSID_SHELL_COMMAND =
            "cmd wifi status | grep -i 'connected to' | cut -d'\"' -f2"
        const val SHELL_COMMAND_TIMEOUT_MS = 2_000L
    }

    enum class WifiDetectionMethod(val value: Int) {
        DEFAULT(0),
        LEGACY(1),
        ROOT(2),
        SHIZUKU(3);

        companion object {
            fun fromValue(value: Int): WifiDetectionMethod =
                entries.find { it.value == value } ?: DEFAULT
        }

        fun needsLocationPermissions(): Boolean {
            return this == DEFAULT || this == LEGACY
        }
    }

    private val connectivityManager =
        appContext.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager?
    private val wifiManager = appContext.getSystemService(Context.WIFI_SERVICE) as WifiManager?
    private val locationManager =
        appContext.getSystemService(Context.LOCATION_SERVICE) as LocationManager?

    private val permissionsChangedFlow = MutableStateFlow(false)

    private val airplaneModeState = MutableStateFlow(appContext.isAirplaneModeOn())
    private val activeCellularNetworks =
        MutableStateFlow<Map<Network, NetworkCapabilities>>(emptyMap())

    private val permissionCheckFlow: Flow<Unit> = callbackFlow {
        val receiver =
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    if (intent.action == actionPermissionCheck) {
                        val isGranted = appContext.hasRequiredLocationPermissions()
                        Timber.d("Received permission check broadcast, isGranted: $isGranted")

                        if (
                            connectivityStateFlow.replayCache
                                .firstOrNull()
                                ?.locationPermissionsGranted != isGranted
                        ) {
                            Timber.d("Location permissions changed, restarting flows")
                            permissionsChangedFlow.update { !permissionsChangedFlow.value }
                        }
                    }
                }
            }

        val flags =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                Context.RECEIVER_NOT_EXPORTED
            } else 0

        appContext.registerReceiver(receiver, IntentFilter(actionPermissionCheck), flags)
        awaitClose { appContext.unregisterReceiver(receiver) }
    }

    private val locationServicesFlow: Flow<Unit> = callbackFlow {
        val receiver =
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    if (intent.action == LOCATION_SERVICES_FILTER) {
                        val enabled = locationManager?.isLocationServicesEnabled() ?: false
                        Timber.d("Location services changed: $enabled")

                        if (
                            connectivityStateFlow.replayCache
                                .firstOrNull()
                                ?.locationServicesEnabled != enabled
                        ) {
                            Timber.d("Location services changed, restarting flows")
                            permissionsChangedFlow.update { !permissionsChangedFlow.value }
                        }
                    }
                }
            }

        val flags =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                Context.RECEIVER_EXPORTED
            } else 0

        appContext.registerReceiver(receiver, IntentFilter(LOCATION_SERVICES_FILTER), flags)
        awaitClose { appContext.unregisterReceiver(receiver) }
    }

    private val airplaneModeReceiverFlow: Flow<Boolean> = callbackFlow {
        val receiver =
            object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    if (intent.action == Intent.ACTION_AIRPLANE_MODE_CHANGED) {
                        val isOn = intent.getBooleanExtra("state", false)
                        Timber.d("Airplane mode changed: $isOn")
                        if (isOn) activeCellularNetworks.value = emptyMap()
                        airplaneModeState.update { isOn }
                    }
                }
            }

        val flags =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                Context.RECEIVER_EXPORTED
            } else 0

        appContext.registerReceiver(
            receiver,
            IntentFilter(Intent.ACTION_AIRPLANE_MODE_CHANGED),
            flags,
        )
        awaitClose { appContext.unregisterReceiver(receiver) }
    }

    init {
        applicationScope.launch { permissionCheckFlow.collect() }
        applicationScope.launch { locationServicesFlow.collect() }
        applicationScope.launch { airplaneModeReceiverFlow.collect() }

        // Set initial airplane mode state
        airplaneModeState.update { appContext.isAirplaneModeOn() }
    }

    // tracking to prevent races that occur when VPN is first activated and to prevent redundant
    // location queries in Legacy mode
    private val lastKnownActiveNetwork =
        MutableStateFlow<ActiveNetwork>(ActiveNetwork.Disconnected())

    private val privateDnsFlow: Flow<PrivateDnsSettings> = callbackFlow {
        val contentResolver = appContext.contentResolver

        val modeUri = Settings.Global.getUriFor("private_dns_mode")
        val specifierUri = Settings.Global.getUriFor("private_dns_specifier")

        val observer =
            object : ContentObserver(null) {
                override fun onChange(selfChange: Boolean) {
                    trySend(getCurrentPrivateDnsSettings())
                }
            }

        contentResolver.registerContentObserver(modeUri, false, observer)
        contentResolver.registerContentObserver(specifierUri, false, observer)

        // initial value
        trySend(getCurrentPrivateDnsSettings())

        awaitClose { contentResolver.unregisterContentObserver(observer) }
    }

    private data class PrivateDnsSettings(val mode: PrivateDnsMode, val hostname: String?)

    private fun getCurrentPrivateDnsSettings(): PrivateDnsSettings {
        val modeStr =
            Settings.Global.getString(appContext.contentResolver, "private_dns_mode") ?: "off"

        val mode =
            when (modeStr) {
                "hostname" -> PrivateDnsMode.HOSTNAME
                "opportunistic" -> PrivateDnsMode.AUTOMATIC
                else -> PrivateDnsMode.OFF
            }

        val hostname =
            Settings.Global.getString(appContext.contentResolver, "private_dns_specifier")

        return PrivateDnsSettings(mode, hostname)
    }

    private fun getDnsServers(network: Network?): List<String> {
        if (network == null) return emptyList()
        val linkProperties = connectivityManager?.getLinkProperties(network) ?: return emptyList()
        return linkProperties.dnsServers.map { it.hostAddress }
    }

    fun hasIpv6Support(network: Network?, activeNetwork: ActiveNetwork): Boolean {
        if (network == null || activeNetwork is ActiveNetwork.Disconnected) return false

        val lp = connectivityManager?.getLinkProperties(network) ?: return false

        val hasGlobalIpv6 =
            lp.linkAddresses.any {
                val addr = it.address
                addr is Inet6Address &&
                    !addr.isLinkLocalAddress &&
                    !addr.isLoopbackAddress &&
                    !addr.isMulticastAddress
            }

        val hasIpv6DefaultRoute =
            lp.routes.any { route -> route.isDefaultRoute && (route.gateway is Inet6Address) }

        val hasNat64Prefix =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                lp.nat64Prefix != null
            } else false

        val hasSupport = (hasGlobalIpv6 && hasIpv6DefaultRoute) || hasNat64Prefix

        return hasSupport
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    private val defaultNetworkFlow: Flow<TransportEvent> =
        combine(configurationListener.detectionMethod, permissionsChangedFlow) { detectionMethod, _
                ->
                detectionMethod
            }
            .flatMapLatest { detectionMethod ->
                callbackFlow {
                    val defaultNetworkCallback =
                        if (
                            Build.VERSION.SDK_INT >= Build.VERSION_CODES.S &&
                                detectionMethod == DEFAULT
                        ) {
                            object :
                                ConnectivityManager.NetworkCallback(FLAG_INCLUDE_LOCATION_INFO) {
                                override fun onAvailable(network: Network) {
                                    Timber.d("Default onAvailable: $network")
                                }

                                override fun onLost(network: Network) {
                                    trySend(TransportEvent.Lost(network))
                                }

                                override fun onCapabilitiesChanged(
                                    network: Network,
                                    caps: NetworkCapabilities,
                                ) {
                                    trySend(TransportEvent.CapabilitiesChanged(network, caps))
                                }
                            }
                        } else {
                            object : ConnectivityManager.NetworkCallback() {
                                override fun onAvailable(network: Network) {
                                    Timber.d("Default onAvailable: $network")
                                }

                                override fun onLost(network: Network) {
                                    trySend(TransportEvent.Lost(network))
                                }

                                override fun onCapabilitiesChanged(
                                    network: Network,
                                    caps: NetworkCapabilities,
                                ) {
                                    trySend(TransportEvent.CapabilitiesChanged(network, caps))
                                }
                            }
                        }
                    connectivityManager?.registerDefaultNetworkCallback(defaultNetworkCallback)

                    trySend(
                        TransportEvent.Permissions(
                            Permissions(
                                locationManager?.isLocationServicesEnabled() ?: false,
                                appContext.hasRequiredLocationPermissions(),
                            )
                        )
                    )

                    awaitClose {
                        connectivityManager?.unregisterNetworkCallback(defaultNetworkCallback)
                    }
                }
            }

    @OptIn(ExperimentalCoroutinesApi::class)
    private val wifiFlow: Flow<TransportEvent> =
        combine(configurationListener.detectionMethod, permissionsChangedFlow) { detectionMethod, _
                ->
                detectionMethod
            }
            .flatMapLatest { detectionMethod -> createWifiNetworkCallbackFlow(detectionMethod) }

    private fun createWifiNetworkCallbackFlow(
        detectionMethod: WifiDetectionMethod
    ): Flow<TransportEvent> = callbackFlow {
        val onAvailable: (Network) -> Unit = { network ->
            // ignore onAvailable has it doesn't contain detailed network information in
            // capabilities
            Timber.d("WiFi onAvailable: $network")
        }
        val onLost: (Network) -> Unit = { network ->
            Timber.d("WiFi onLost: $network")
            trySend(TransportEvent.Lost(network))
        }
        val onCapabilitiesChanged: (Network, NetworkCapabilities) -> Unit = { network, caps ->
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)) {
                trySend(TransportEvent.CapabilitiesChanged(network, caps))
            }
        }

        val wifiCallback =
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S && detectionMethod == DEFAULT) {
                object : ConnectivityManager.NetworkCallback(FLAG_INCLUDE_LOCATION_INFO) {
                    override fun onAvailable(network: Network) = onAvailable(network)

                    override fun onLost(network: Network) = onLost(network)

                    override fun onCapabilitiesChanged(
                        network: Network,
                        caps: NetworkCapabilities,
                    ) = onCapabilitiesChanged(network, caps)
                }
            } else {
                object : ConnectivityManager.NetworkCallback() {
                    override fun onAvailable(network: Network) = onAvailable(network)

                    override fun onLost(network: Network) = onLost(network)

                    override fun onCapabilitiesChanged(
                        network: Network,
                        caps: NetworkCapabilities,
                    ) = onCapabilitiesChanged(network, caps)
                }
            }

        val request =
            NetworkRequest.Builder()
                .apply { addTransportType(NetworkCapabilities.TRANSPORT_WIFI) }
                .build()

        connectivityManager?.registerNetworkCallback(request, wifiCallback)

        trySend(TransportEvent.Unknown)

        awaitClose {
            runCatching { connectivityManager?.unregisterNetworkCallback(wifiCallback) }
                .onFailure { Timber.e(it, "Error unregistering WiFi network callback") }
        }
    }

    private val cellularFlow: Flow<TransportEvent> = callbackFlow {
        val onAvailable: (Network) -> Unit = { network ->
            Timber.d("Cellular onAvailable: $network")
            val caps = connectivityManager?.getNetworkCapabilities(network)
            if (caps != null && caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                activeCellularNetworks.update { it + (network to caps) }
                trySend(TransportEvent.CapabilitiesChanged(network, caps))
            }
        }

        val onLost: (Network) -> Unit = { network ->
            Timber.d("Cellular onLost: $network")
            activeCellularNetworks.update { it - network }
            trySend(TransportEvent.Lost(network))
        }

        val onCapabilitiesChanged: (Network, NetworkCapabilities) -> Unit = { network, caps ->
            if (caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR)) {
                activeCellularNetworks.update { it + (network to caps) }
                trySend(TransportEvent.CapabilitiesChanged(network, caps))
            }
        }

        val cellularCallback =
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = onAvailable(network)

                override fun onLost(network: Network) = onLost(network)

                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) =
                    onCapabilitiesChanged(network, caps)
            }

        val request =
            NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
                .build()
        connectivityManager?.registerNetworkCallback(request, cellularCallback)
        trySend(TransportEvent.Unknown)
        awaitClose {
            runCatching { connectivityManager?.unregisterNetworkCallback(cellularCallback) }
                .onFailure { Timber.e(it, "Error unregistering cellular network callback") }
        }
    }

    private val ethernetFlow: Flow<TransportEvent> = callbackFlow {
        val onAvailable: (Network) -> Unit = { network ->
            Timber.d("Ethernet onAvailable: $network")
        }
        val onLost: (Network) -> Unit = { network ->
            Timber.d("Ethernet onLost: $network")
            trySend(TransportEvent.Lost(network))
        }
        val onCapabilitiesChanged: (Network, NetworkCapabilities) -> Unit = { network, caps ->
            Timber.d("Ethernet onCapabilitiesChanged: $network")
            trySend(TransportEvent.CapabilitiesChanged(network, caps))
        }

        val ethernetCallback =
            object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) = onAvailable(network)

                override fun onLost(network: Network) = onLost(network)

                override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) =
                    onCapabilitiesChanged(network, caps)
            }

        val request =
            NetworkRequest.Builder()
                .apply { addTransportType(NetworkCapabilities.TRANSPORT_ETHERNET) }
                .build()

        connectivityManager?.registerNetworkCallback(request, ethernetCallback)

        trySend(TransportEvent.Unknown)

        awaitClose {
            runCatching { connectivityManager?.unregisterNetworkCallback(ethernetCallback) }
                .onFailure { Timber.e(it, "Error unregistering ethernet network callback") }
        }
    }

    private suspend fun getSsidByDetectionMethod(
        detectionMethod: WifiDetectionMethod?,
        networkCapabilities: NetworkCapabilities?,
        network: Network?,
    ): String {
        val method = detectionMethod ?: DEFAULT
        return try {
                when (method) {
                        DEFAULT ->
                            networkCapabilities?.getWifiSsid()
                                ?: wifiManager?.getWifiSsid()
                                ?: ANDROID_UNKNOWN_SSID
                        LEGACY -> {
                            // prevent redundant location queries in legacy mode
                            val lastActive = lastKnownActiveNetwork.value
                            if (
                                lastActive is ActiveNetwork.Wifi &&
                                    lastActive.networkId == network?.toString()
                            ) {
                                if (lastActive.ssid != ANDROID_UNKNOWN_SSID) {
                                    Timber.d(
                                        "Using last active network SSID for same network to prevent redundant location query"
                                    )
                                    return lastActive.ssid
                                }
                            }
                            Timber.d("Triggering new location ping")
                            wifiManager?.getWifiSsid() ?: ANDROID_UNKNOWN_SSID
                        }
                        ROOT ->
                            withTimeoutOrNull(SHELL_COMMAND_TIMEOUT_MS.milliseconds) {
                                configurationListener.runRootShellCommand(WIFI_SSID_SHELL_COMMAND)
                            } ?: ANDROID_UNKNOWN_SSID
                        SHIZUKU ->
                            withTimeoutOrNull(SHELL_COMMAND_TIMEOUT_MS.milliseconds) {
                                ShizukuShell(applicationScope)
                                    .singleResponseCommand(WIFI_SSID_SHELL_COMMAND)
                            } ?: ANDROID_UNKNOWN_SSID
                    }
                    .trim()
                    .replace(Regex("[\n\r]"), "")
            } catch (e: Exception) {
                Timber.e(e, "Failed to get SSID with method: ${method.name}")
                ANDROID_UNKNOWN_SSID
            }
            .also { Timber.d("Current SSID via ${method.name}: $it") }
    }

    private fun hasValidatedInternet(caps: NetworkCapabilities?): Boolean {
        if (caps == null) return false
        return caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) &&
            caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED) &&
            (Build.VERSION.SDK_INT < Build.VERSION_CODES.P ||
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED))
    }

    // default network events don't contain detailed capability information of underlying networks,
    // so we need to track separately
    private data class NetworkData(
        val defaultNetworkEvent: TransportEvent,
        val wifiNetworkEvent: TransportEvent,
        val cellularEvent: TransportEvent,
        val ethernetEvent: TransportEvent,
    )

    // combine our network flows to keep sync
    private val networkFlows: Flow<NetworkData> =
        combine(defaultNetworkFlow, wifiFlow, cellularFlow, ethernetFlow) {
            defaultEvent,
            wifiEvent,
            cellularEvent,
            ethernetEvent ->
            NetworkData(defaultEvent, wifiEvent, cellularEvent, ethernetEvent)
        }

    // For multi-sim selection, prefers foreground, then validated internet, then not suspended
    private fun pickBestCellularNetwork(): Network? {
        if (activeCellularNetworks.value.isEmpty()) return null

        return activeCellularNetworks.value.entries
            .maxByOrNull { (_, caps) ->
                var score = 0
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_FOREGROUND)) score += 100
                if (hasValidatedInternet(caps)) score += 50
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED))
                    score += 20
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED))
                    score += 10
                if (caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)) score += 5
                score
            }
            ?.key
    }

    @OptIn(FlowPreview::class)
    override val connectivityStateFlow: SharedFlow<ConnectivityState> =
        combine(
                networkFlows,
                airplaneModeState,
                configurationListener.detectionMethod,
                privateDnsFlow,
            ) { networkData, isAirplaneOn, detectionMethod, privateDnsSettings ->
                val defaultEvent = networkData.defaultNetworkEvent
                val permissions =
                    when (defaultEvent) {
                        is TransportEvent.Permissions -> defaultEvent.permissions
                        else ->
                            Permissions(
                                locationManager?.isLocationServicesEnabled() ?: false,
                                appContext.hasRequiredLocationPermissions(),
                            )
                    }

                // determine default network capabilities and network
                val (defaultCaps, defaultNetwork) =
                    when (defaultEvent) {
                        is TransportEvent.CapabilitiesChanged ->
                            defaultEvent.networkCapabilities to defaultEvent.network
                        else ->
                            connectivityManager?.activeNetwork?.let { network ->
                                connectivityManager.getNetworkCapabilities(network) to network
                            } ?: (null to null)
                    }

                if (defaultCaps == null || defaultNetwork == null) {
                    return@combine ConnectivityState(
                        activeNetwork = ActiveNetwork.Disconnected(),
                        locationPermissionsGranted = permissions.locationPermissionGranted,
                        locationServicesEnabled = permissions.locationServicesEnabled,
                        airplaneModeOn = isAirplaneOn,
                        vpnState = VpnState.Inactive,
                    )
                }

                val isVpnActive = defaultCaps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)

                val vpnState: VpnState =
                    if (!isVpnActive) {
                        VpnState.Inactive
                    } else {
                        VpnState.Active(
                            hasInternet =
                                defaultCaps.hasCapability(
                                    NetworkCapabilities.NET_CAPABILITY_VALIDATED
                                )
                        )
                    }

                val physicalNetwork: ActiveNetwork =
                    when {
                        networkData.ethernetEvent is TransportEvent.CapabilitiesChanged &&
                            networkData.ethernetEvent.networkCapabilities?.hasTransport(
                                NetworkCapabilities.TRANSPORT_ETHERNET
                            ) == true -> {
                            ActiveNetwork.Ethernet(networkData.ethernetEvent.network)
                        }

                        networkData.wifiNetworkEvent is TransportEvent.CapabilitiesChanged &&
                            networkData.wifiNetworkEvent.networkCapabilities?.let { caps ->
                                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
                            } == true -> {

                            val wifiEvent = networkData.wifiNetworkEvent
                            val currentNetworkId = wifiEvent.network.toString()
                            val lastActive = lastKnownActiveNetwork.value

                            // Use cache in legacy mode
                            val (ssid, securityType) =
                                if (
                                    detectionMethod == LEGACY &&
                                        lastActive is ActiveNetwork.Wifi &&
                                        lastActive.networkId == currentNetworkId &&
                                        lastActive.ssid != ANDROID_UNKNOWN_SSID
                                ) {
                                    Timber.d(
                                        "Using cached SSID and Security Type to prevent location ping"
                                    )
                                    lastActive.ssid to lastActive.securityType
                                } else {
                                    // Fallback
                                    val fetchedSsid =
                                        getSsidByDetectionMethod(
                                            detectionMethod,
                                            wifiEvent.networkCapabilities,
                                            wifiEvent.network,
                                        )
                                    val fetchedSecurity =
                                        if (
                                            detectionMethod == DEFAULT &&
                                                Build.VERSION.SDK_INT >= Build.VERSION_CODES.S
                                        ) {
                                            wifiEvent.networkCapabilities.getWifiSecurityType()
                                        } else {
                                            wifiManager?.getLegacySecurityType()
                                        }
                                    fetchedSsid to fetchedSecurity
                                }

                            ActiveNetwork.Wifi(
                                ssid,
                                securityType,
                                currentNetworkId,
                                wifiEvent.network,
                            )
                        }
                        else -> {
                            val cellularNetwork =
                                pickBestCellularNetwork()
                                    ?: activeCellularNetworks.value.keys.firstOrNull()

                            if (cellularNetwork != null) {
                                ActiveNetwork.Cellular(cellularNetwork)
                            } else {
                                ActiveNetwork.Disconnected()
                            }
                        }
                    }

                lastKnownActiveNetwork.value = physicalNetwork

                val underlyingNetwork: Network? =
                    when (physicalNetwork) {
                        is ActiveNetwork.Wifi -> physicalNetwork.network
                        is ActiveNetwork.Cellular -> physicalNetwork.network
                        is ActiveNetwork.Ethernet -> physicalNetwork.network
                        else -> null
                    }

                val effectiveDns =
                    DnsInfo(
                        servers = getDnsServers(defaultNetwork),
                        privateDnsMode = privateDnsSettings.mode,
                        privateDnsHostname = privateDnsSettings.hostname,
                    )
                val underlyingDns =
                    DnsInfo(
                        servers = getDnsServers(underlyingNetwork),
                        privateDnsMode = privateDnsSettings.mode,
                        privateDnsHostname = privateDnsSettings.hostname,
                    )

                val physicalCaps: NetworkCapabilities? =
                    when (physicalNetwork) {
                        is ActiveNetwork.Wifi ->
                            (networkData.wifiNetworkEvent as? TransportEvent.CapabilitiesChanged)
                                ?.networkCapabilities
                        is ActiveNetwork.Cellular ->
                            activeCellularNetworks.value[physicalNetwork.network]
                        is ActiveNetwork.Ethernet ->
                            (networkData.ethernetEvent as? TransportEvent.CapabilitiesChanged)
                                ?.networkCapabilities
                        else -> null
                    }

                val hasValidatedInternet = hasValidatedInternet(physicalCaps)

                ConnectivityState(
                    activeNetwork = physicalNetwork,
                    locationPermissionsGranted = permissions.locationPermissionGranted,
                    locationServicesEnabled = permissions.locationServicesEnabled,
                    vpnState = vpnState,
                    airplaneModeOn = isAirplaneOn,
                    effectiveDnsInfo = effectiveDns,
                    underlyingDnsInfo = underlyingDns,
                    hasIpv6 = hasIpv6Support(underlyingNetwork, physicalNetwork),
                    hasValidatedInternet = hasValidatedInternet,
                )
            }
            .distinctUntilChanged()
            .debounce(300.milliseconds)
            .shareIn(applicationScope, SharingStarted.Eagerly, replay = 1)

    // utility to send local broadcast to trigger a recheck of location permissions onResume,
    // especially for getting SSID
    // that we did not have permission to read before, will trigger a recreation of the Wi-Fi flows
    // if permission was changed
    override fun checkPermissionsAndUpdateState() {
        val action = actionPermissionCheck
        val intent = Intent(action).apply { setPackage(appContext.packageName) }
        Timber.d("Sending broadcast: $action")
        appContext.sendBroadcast(intent)
    }
}
