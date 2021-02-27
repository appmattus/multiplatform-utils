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

class PlatformDigestSHA256Test {

    /**
     * Test SHA-256 implementation.
     */
    @Test
    fun testSHA256() {
        val dig = PlatformDigest().createDigest(Algorithm.SHA256) ?: fail()
        testKat(
            dig, "abc",
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        testKat(
            dig, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlm"
                    + "nomnopnopq",
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        )
        testKatMillionA(
            dig,
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        )
    }
}
