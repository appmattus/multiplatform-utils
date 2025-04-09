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

import com.appmattus.battery.ChargingStatus.Status.Charging
import com.appmattus.battery.ChargingStatus.Status.Discharging
import com.appmattus.battery.ChargingStatus.Status.Full
import com.appmattus.battery.ChargingStatus.Status.Unavailable
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import platform.Foundation.NSNotificationCenter
import platform.Foundation.NSProcessInfo
import platform.UIKit.UIDevice
import platform.UIKit.UIDeviceBatteryState
import platform.UIKit.UIDeviceBatteryStateDidChangeNotification

actual class Battery {

    actual val batteryLevel: Int
        get() = with(UIDevice.currentDevice) {
            batteryMonitoringEnabled = true
            when {
                NSProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != null -> BATTERY_MAX_VALUE
                batteryState == UIDeviceBatteryState.UIDeviceBatteryStateUnknown -> -1
                else -> (batteryLevel * BATTERY_MAX_VALUE).toInt()
            }
        }

    actual val chargingStatus: Flow<ChargingStatus>
        get() = callbackFlow {
            UIDevice.currentDevice.batteryMonitoringEnabled = true

            trySend(UIDevice.currentDevice.batteryState.asChargingStatus)

            val observer = NSNotificationCenter.defaultCenter.addObserverForName(
                name = UIDeviceBatteryStateDidChangeNotification,
                `object` = null,
                queue = null,
                usingBlock = {
                    trySend(UIDevice.currentDevice.batteryState.asChargingStatus)
                }
            )

            awaitClose {
                NSNotificationCenter.defaultCenter.removeObserver(observer)
            }
        }

    companion object {
        @Suppress("REDUNDANT_ELSE_IN_WHEN", "KotlinRedundantDiagnosticSuppress")
        private val UIDeviceBatteryState.asChargingStatus
            get() = if (NSProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != null) {
                ChargingStatus(Full)
            } else {
                when (this) {
                    UIDeviceBatteryState.UIDeviceBatteryStateCharging -> ChargingStatus(Charging)
                    UIDeviceBatteryState.UIDeviceBatteryStateFull -> ChargingStatus(Full)
                    UIDeviceBatteryState.UIDeviceBatteryStateUnplugged -> ChargingStatus(Discharging)
                    UIDeviceBatteryState.UIDeviceBatteryStateUnknown -> ChargingStatus(Unavailable)
                    else -> ChargingStatus(Unavailable)
                }
            }

        private const val BATTERY_MAX_VALUE = 100
    }
}
