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

package com.appmattus.battery

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.BatteryManager
import com.appmattus.battery.ChargingStatus.Status.Charging
import com.appmattus.battery.ChargingStatus.Status.Discharging
import com.appmattus.battery.ChargingStatus.Status.Full
import com.appmattus.battery.ChargingStatus.Status.Unavailable
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow

actual class Battery(private val context: Context) {

    actual val batteryLevel: Int
        get() {
            val batteryManager = context.getSystemService(Context.BATTERY_SERVICE) as BatteryManager
            return batteryManager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
        }

    actual val chargingStatus: Flow<ChargingStatus>
        get() = callbackFlow {
            val receiver = object : BroadcastReceiver() {
                override fun onReceive(context: Context, intent: Intent) {
                    when (intent.getIntExtra(BatteryManager.EXTRA_STATUS, -1)) {
                        BatteryManager.BATTERY_STATUS_CHARGING -> ChargingStatus(Charging)
                        BatteryManager.BATTERY_STATUS_FULL -> ChargingStatus(Full)
                        BatteryManager.BATTERY_STATUS_DISCHARGING -> ChargingStatus(Discharging)
                        else -> ChargingStatus(Unavailable)
                    }.let {
                        trySend(it)
                    }
                }
            }

            context.registerReceiver(receiver, IntentFilter(Intent.ACTION_BATTERY_CHANGED))

            awaitClose {
                context.unregisterReceiver(receiver)
            }
        }
}
