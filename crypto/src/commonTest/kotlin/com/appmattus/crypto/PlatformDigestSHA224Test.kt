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
import fr.cryptohash.testKatMillionA
import kotlin.test.Test
import kotlin.test.fail

class PlatformDigestSHA224Test {

    /**
     * Test SHA-224 implementation.
     */
    @Test
    fun testSHA224() {
        val dig = PlatformDigest().createDigest(Algorithm.SHA224) ?: fail()
        testKat(
            dig, "abc",
            "23097d223405d8228642a477bda255b32aadbce4bda0b3f7e36c9da7"
        )
        testKat(
            dig, ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlm"
                    + "nomnopnopq"),
            "75388b16512776cc5dba5da1fd890150b0c6455cb4f58b1952522525"
        )
        testKatMillionA(
            dig,
            "20794655980c91d8bbb4c1ea97618a4bf03f42581948b2ee4ee7ad67"
        )
    }
}
