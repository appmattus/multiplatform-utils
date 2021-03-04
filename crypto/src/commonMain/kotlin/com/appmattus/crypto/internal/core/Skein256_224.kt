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
 * This class implements the Skein-256-224 digest algorithm
 */
@Suppress("ClassName")
internal class Skein256_224 : SkeinSmallCore<Skein256_224>() {

    override val initVal: LongArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 28

    override fun dup(): Skein256_224 {
        return Skein256_224()
    }

    companion object {
        /** The initial value for Skein-256-224.  */
        @Suppress("EXPERIMENTAL_API_USAGE", "EXPERIMENTAL_UNSIGNED_LITERALS")
        private val initVal = longArrayOf(
            0xc6098a8c9ae5ea0bUL.toLong(),
            0x876d568608c5191cUL.toLong(),
            0x99cb88d7d7f53884UL.toLong(),
            0x384bddb1aeddb5deL
        )
    }
}
