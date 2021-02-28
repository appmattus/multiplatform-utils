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

class PlatformDigestSHA1Test {

    /**
     * Test SHA-1 implementation.
     */
    @Test
    fun testSHA1() {
        val dig = PlatformDigest().createDigest(Algorithm.SHA1) ?: fail()
        testKat(dig, "", "da39a3ee5e6b4b0d3255bfef95601890afd80709")
        testKat(dig, "abc", "a9993e364706816aba3e25717850c26c9cd0d89d")
        testKat(
            dig, ("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlm"
                    + "nomnopnopq"),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        )
        testKatMillionA(
            dig,
            "34aa973cd4c4daa4f61eeb2bdbad27316534016f"
        )
    }
}
