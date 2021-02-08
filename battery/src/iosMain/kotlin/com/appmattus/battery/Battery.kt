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

package com.appmattus.battery

import com.appmattus.battery.ChargingStatus.Status.Charging
import com.appmattus.battery.ChargingStatus.Status.Discharging
import com.appmattus.battery.ChargingStatus.Status.Full
import com.appmattus.battery.ChargingStatus.Status.Unavailable
import kotlinx.coroutines.channels.SendChannel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.callbackFlow
import kotlinx.coroutines.runBlocking
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
                NSProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != null -> 100
                batteryState == UIDeviceBatteryState.UIDeviceBatteryStateUnknown -> -1
                else -> (batteryLevel * 100).toInt()
            }
        }

    @Suppress("EXPERIMENTAL_API_USAGE")
    actual val chargingStatus: Flow<ChargingStatus>
        get() = callbackFlow<ChargingStatus> {
            UIDevice.currentDevice.batteryMonitoringEnabled = true

            sendBlocking(UIDevice.currentDevice.batteryState.asChargingStatus)

            val observer = NSNotificationCenter.defaultCenter.addObserverForName(
                name = UIDeviceBatteryStateDidChangeNotification,
                `object` = null,
                queue = null,
                usingBlock = {
                    sendBlocking(UIDevice.currentDevice.batteryState.asChargingStatus)
                }
            )

            awaitClose {
                NSNotificationCenter.defaultCenter.removeObserver(observer)
            }
        }

    companion object {
        private val UIDeviceBatteryState.asChargingStatus
            get() = if (NSProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != null) ChargingStatus(Full) else when (this) {
                UIDeviceBatteryState.UIDeviceBatteryStateCharging -> ChargingStatus(Charging)
                UIDeviceBatteryState.UIDeviceBatteryStateFull -> ChargingStatus(Full)
                UIDeviceBatteryState.UIDeviceBatteryStateUnknown -> ChargingStatus(Unavailable)
                UIDeviceBatteryState.UIDeviceBatteryStateUnplugged -> ChargingStatus(Discharging)
            }

        private fun <E> SendChannel<E>.sendBlocking(element: E) {
            // fast path
            if (offer(element)) {
                return
            }
            // slow path
            runBlocking {
                send(element)
            }
        }
    }
}
