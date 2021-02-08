/*
 * Copyright 2021 Appmattus Limited
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

import android.annotation.TargetApi
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build.VERSION
import android.os.Build.VERSION_CODES
import com.appmattus.connectivity.ConnectivityStatus.Status.Mobile
import com.appmattus.connectivity.ConnectivityStatus.Status.None
import com.appmattus.connectivity.ConnectivityStatus.Status.Wifi
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.channels.sendBlocking
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow

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

    @TargetApi(VERSION_CODES.M)
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

    @Suppress("EXPERIMENTAL_API_USAGE")
    actual val connectivityStatus: Flow<ConnectivityStatus>
        get() = callbackFlow {
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    sendBlocking(connectivity)
                }
            }

            context.registerReceiver(receiver, IntentFilter(ConnectivityManager.CONNECTIVITY_ACTION))

            awaitClose {
                context.unregisterReceiver(receiver)
            }
        }
}
