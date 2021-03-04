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
 * This class implements the Skein-512-160 digest algorithm
 */
@Suppress("ClassName")
internal class Skein512_160 : SkeinBigCore<Skein512_160>() {

    override val initVal: LongArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 20

    override fun dup(): Skein512_160 {
        return Skein512_160()
    }

    companion object {
        /** The initial value for Skein-512-160.  */
        @Suppress("EXPERIMENTAL_API_USAGE", "EXPERIMENTAL_UNSIGNED_LITERALS")
        private val initVal = longArrayOf(
            0x28b81a2ae013bd91L, 0xc2f11668b5bdf78fUL.toLong(),
            0x1760d8f3f6a56f12L, 0x4fb747588239904fL,
            0x21ede07f7eaf5056L, 0xd908922e63ed70b8UL.toLong(),
            0xb8ec76ffeccb52faUL.toLong(), 0x01a47bb8a3f27a6eL
        )
    }
}
