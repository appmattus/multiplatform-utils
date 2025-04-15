/*
 * Copyright 2021-2025 Appmattus Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.appmattus.connectivity

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build.VERSION
import android.os.Build.VERSION_CODES
import androidx.annotation.RequiresApi
import com.appmattus.connectivity.ConnectivityStatus.Status.Mobile
import com.appmattus.connectivity.ConnectivityStatus.Status.None
import com.appmattus.connectivity.ConnectivityStatus.Status.Wifi
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.flowOn
import kotlinx.coroutines.launch

actual class Connectivity(private val context: Context) {

    private val connectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager

    @Suppress("MemberNameEqualsClassName")
    actual val connectivity: ConnectivityStatus
        get() = if (VERSION.SDK_INT >= VERSION_CODES.M) {
            getNetworkTypeApi23()
        } else {
            getNetworkTypeLegacy()
        }

    @RequiresApi(VERSION_CODES.M)
    private fun getNetworkTypeApi23(): ConnectivityStatus {
        val network = connectivityManager.activeNetwork
        val capabilities =
            connectivityManager.getNetworkCapabilities(network) ?: return ConnectivityStatus(None)

        return when {
            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                capabilities.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> ConnectivityStatus(Wifi)

            capabilities.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> ConnectivityStatus(Mobile)

            else -> ConnectivityStatus(None)
        }
    }

    @Suppress("DEPRECATION")
    private fun getNetworkTypeLegacy(): ConnectivityStatus {
        // handle type for Android versions less than Android 9
        val info = connectivityManager.activeNetworkInfo
        if (info == null || !info.isConnected) {
            return ConnectivityStatus(None)
        }
        return when (info.type) {
            ConnectivityManager.TYPE_ETHERNET,
            ConnectivityManager.TYPE_WIFI,
            ConnectivityManager.TYPE_WIMAX -> ConnectivityStatus(Wifi)

            ConnectivityManager.TYPE_MOBILE,
            ConnectivityManager.TYPE_MOBILE_DUN,
            ConnectivityManager.TYPE_MOBILE_HIPRI -> ConnectivityStatus(Mobile)

            else -> ConnectivityStatus(None)
        }
    }

    actual val connectivityStatus: Flow<ConnectivityStatus>
        get() = callbackFlow {
            var statusJob: Job? = null

            fun updateNetworkStatus() {
                statusJob?.cancel()
                statusJob = launch {
                    delay(StatusCheckDelay)
                    trySend(connectivity)
                }
            }

            val networkCallback = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    super.onAvailable(network)
                    updateNetworkStatus()
                }

                override fun onLost(network: Network) {
                    super.onLost(network)
                    updateNetworkStatus()
                }
            }

            val networkChangeFilter = NetworkRequest.Builder().build()
            connectivityManager.registerNetworkCallback(networkChangeFilter, networkCallback)

            trySend(connectivity)

            awaitClose {
                connectivityManager.unregisterNetworkCallback(networkCallback)
            }
        }.flowOn(Dispatchers.Unconfined).distinctUntilChanged()

    companion object {
        private const val StatusCheckDelay = 100L
    }
}
