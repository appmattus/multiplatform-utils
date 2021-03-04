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

package com.appmattus.crypto.internal.core

import com.appmattus.crypto.internal.core.sphlib.SkeinSmallCore

/**
 * This class implements the Skein-256-128 digest algorithm
 */
@Suppress("ClassName")
internal class Skein256_128 : SkeinSmallCore<Skein256_128>() {

    override val initVal: LongArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 16

    override fun dup(): Skein256_128 {
        return Skein256_128()
    }

    companion object {
        /** The initial value for Skein-256-128.  */
        @Suppress("EXPERIMENTAL_API_USAGE", "EXPERIMENTAL_UNSIGNED_LITERALS")
        private val initVal = longArrayOf(
            0xe1111906964d7260UL.toLong(),
            0x883daaa77c8d811cUL.toLong(),
            0x10080df491960f7aL,
            0xccf7dde5b45bc1c2UL.toLong()
        )
    }
}
