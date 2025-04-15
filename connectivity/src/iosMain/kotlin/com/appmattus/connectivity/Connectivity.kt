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

import com.appmattus.connectivity.ConnectivityStatus.Status.Mobile
import com.appmattus.connectivity.ConnectivityStatus.Status.None
import com.appmattus.connectivity.ConnectivityStatus.Status.Wifi
import kotlinx.cinterop.COpaquePointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.StableRef
import kotlinx.cinterop.alloc
import kotlinx.cinterop.asStableRef
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.staticCFunction
import kotlinx.cinterop.value
import kotlinx.coroutines.channels.SendChannel
import kotlinx.coroutines.channels.awaitClose
import kotlinx.coroutines.flow.callbackFlow
import platform.CoreFoundation.CFRelease
import platform.CoreFoundation.CFRunLoopGetCurrent
import platform.CoreFoundation.kCFRunLoopDefaultMode
import platform.Foundation.NSProcessInfo
import platform.SystemConfiguration.SCNetworkReachabilityContext
import platform.SystemConfiguration.SCNetworkReachabilityCreateWithName
import platform.SystemConfiguration.SCNetworkReachabilityFlags
import platform.SystemConfiguration.SCNetworkReachabilityFlagsVar
import platform.SystemConfiguration.SCNetworkReachabilityGetFlags
import platform.SystemConfiguration.SCNetworkReachabilityRef
import platform.SystemConfiguration.SCNetworkReachabilityScheduleWithRunLoop
import platform.SystemConfiguration.SCNetworkReachabilitySetCallback
import platform.SystemConfiguration.SCNetworkReachabilityUnscheduleFromRunLoop
import platform.SystemConfiguration.kSCNetworkReachabilityFlagsConnectionOnDemand
import platform.SystemConfiguration.kSCNetworkReachabilityFlagsConnectionOnTraffic
import platform.SystemConfiguration.kSCNetworkReachabilityFlagsConnectionRequired
import platform.SystemConfiguration.kSCNetworkReachabilityFlagsInterventionRequired
import platform.SystemConfiguration.kSCNetworkReachabilityFlagsIsWWAN
import platform.SystemConfiguration.kSCNetworkReachabilityFlagsReachable

@OptIn(ExperimentalForeignApi::class)
actual class Connectivity(private val nodename: String = "example.com") {

    @Suppress("MemberNameEqualsClassName")
    actual val connectivity: ConnectivityStatus
        get() = memScoped {
            val reachability = SCNetworkReachabilityCreateWithName(null, nodename)!!

            val flags = alloc<SCNetworkReachabilityFlagsVar>().run {
                SCNetworkReachabilityGetFlags(reachability, ptr)
                value
            }

            CFRelease(reachability)

            flags.asConnectivityStatus
        }

    actual val connectivityStatus
        get() = callbackFlow<ConnectivityStatus> {
            val reachability = SCNetworkReachabilityCreateWithName(null, nodename)!!

            memScoped {
                val context = alloc<SCNetworkReachabilityContext>()
                context.info = StableRef.create(this@callbackFlow).asCPointer()

                val callbackSuccessful = SCNetworkReachabilitySetCallback(
                    target = reachability,
                    callout = staticCFunction { _: SCNetworkReachabilityRef?, flags: SCNetworkReachabilityFlags, info: COpaquePointer? ->
                        info?.asStableRef<SendChannel<ConnectivityStatus>>()?.get()?.trySend(flags.asConnectivityStatus)
                        Unit
                    },
                    context = context.ptr
                )

                if (callbackSuccessful) {
                    SCNetworkReachabilityScheduleWithRunLoop(
                        target = reachability,
                        runLoop = CFRunLoopGetCurrent(),
                        runLoopMode = kCFRunLoopDefaultMode
                    )
                }
            }

            awaitClose {
                SCNetworkReachabilityUnscheduleFromRunLoop(reachability, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode)
            }
        }

    companion object {
        private val SCNetworkReachabilityFlags.asConnectivityStatus: ConnectivityStatus
            get() = when {
                !reachable -> None
                NSProcessInfo.processInfo.environment["SIMULATOR_DEVICE_NAME"] != null -> Wifi
                isWWAN -> Mobile
                (connectionOnTraffic || connectionOnDemand) && !interventionRequired -> Wifi
                !connectionRequired -> Wifi
                else -> None
            }.let(::ConnectivityStatus)

        private val SCNetworkReachabilityFlags.connectionOnDemand: Boolean
            get() = (kSCNetworkReachabilityFlagsConnectionOnDemand and this) != 0.toUInt()

        private val SCNetworkReachabilityFlags.connectionOnTraffic: Boolean
            get() = (kSCNetworkReachabilityFlagsConnectionOnTraffic and this) != 0.toUInt()

        private val SCNetworkReachabilityFlags.connectionRequired: Boolean
            get() = (kSCNetworkReachabilityFlagsConnectionRequired and this) != 0.toUInt()

        private val SCNetworkReachabilityFlags.interventionRequired: Boolean
            get() = (kSCNetworkReachabilityFlagsInterventionRequired and this) != 0.toUInt()

        private val SCNetworkReachabilityFlags.isWWAN: Boolean
            get() = (kSCNetworkReachabilityFlagsIsWWAN and this) != 0.toUInt()

        private val SCNetworkReachabilityFlags.reachable: Boolean
            get() = (kSCNetworkReachabilityFlagsReachable and this) != 0.toUInt()
    }
}
