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

import com.appmattus.crypto.internal.core.sphlib.SkeinBigCore

/**
 * This class implements the Skein-512-128 digest algorithm
 */
@Suppress("ClassName")
internal class Skein512_128 : SkeinBigCore<Skein512_128>() {

    override val initVal: LongArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 16

    override fun dup(): Skein512_128 {
        return Skein512_128()
    }

    companion object {
        /** The initial value for Skein-512-128.  */
        @Suppress("EXPERIMENTAL_API_USAGE", "EXPERIMENTAL_UNSIGNED_LITERALS")
        private val initVal = longArrayOf(
            0xa8bc7bf36fbf9f52UL.toLong(), 0x1e9872cebd1af0aaL,
            0x309b1790b32190d3L, 0xbcfbb8543f94805cUL.toLong(),
            0x0da61bcd6e31b11bL, 0x1a18ebead46a32e3L,
            0xa2cc5b18ce84aa82UL.toLong(), 0x6982ab289d46982dL
        )
    }
}
