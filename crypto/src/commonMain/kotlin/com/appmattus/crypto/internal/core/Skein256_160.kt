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
 * This class implements the Skein-256-160 digest algorithm
 */
@Suppress("ClassName")
internal class Skein256_160 : SkeinSmallCore<Skein256_160>() {

    override val initVal: LongArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 20

    override fun dup(): Skein256_160 {
        return Skein256_160()
    }

    companion object {
        /** The initial value for Skein-256-160.  */
        @Suppress("EXPERIMENTAL_API_USAGE", "EXPERIMENTAL_UNSIGNED_LITERALS")
        private val initVal = longArrayOf(
            0x1420231472825e98L,
            0x2ac4e9a25a77e590L,
            0xd47a58568838d63eUL.toLong(),
            0x2dd2e4968586ab7dL
        )
    }
}
