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

package com.appmattus.crypto

import fr.cryptohash.testKat
import kotlin.test.Test

/**
 * Test SHA-512/256 implementation.
 */
abstract class SHA512_224Base {

    abstract fun digest(): Digest<*>

    /**
     * Tests from https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/SHA512_224.pdf
     */
    @Test
    fun nistAbc() {
        testKat(
            dig = digest(),
            data = "abc",
            ref = "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa"
        )
    }

    @Test
    fun nist112chars() {
        testKat(
            dig = digest(),
            data = "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
            ref = "23fec5bb94d60b23308192640b0c453335d664734fe40e7268674af9"
        )
    }
}
