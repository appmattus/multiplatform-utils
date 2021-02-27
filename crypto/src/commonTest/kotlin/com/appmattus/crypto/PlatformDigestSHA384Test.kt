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

class PlatformDigestSHA384Test {

    /**
     * Test SHA-384 implementation.
     */
    @Test
    fun testSHA384() {
        val dig = PlatformDigest().createDigest(Algorithm.SHA384) ?: fail()
        testKat(
            dig, "abc", "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded163"
                    + "1a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7"
        )
        testKat(
            dig, "abcdefghbcdefghicdefghijdefghijkefghijklfghij"
                    + "klmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnop"
                    + "qrsmnopqrstnopqrstu", "09330c33f71147e83d192fc782cd1b4753111b173b3b05d2"
                    + "2fa08086e3b0f712fcc7c71a557e2db966c3e9fa91746039"
        )
        testKatMillionA(
            dig, "9d0e1809716474cb086e834e310a4a1ced149e9c00f24852"
                    + "7972cec5704c2a5b07b8b3dc38ecc4ebae97ddd87f3d8985"
        )
    }
}
