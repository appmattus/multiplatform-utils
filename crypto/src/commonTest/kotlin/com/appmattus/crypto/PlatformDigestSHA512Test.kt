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

class PlatformDigestSHA512Test {

    /**
     * Test SHA-512 implementation.
     */
    @Test
    fun testSHA512() {
        val dig = PlatformDigest().createDigest(Algorithm.SHA512) ?: fail()
        println(1)
        testKat(
            dig, "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                    + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
        println(2)
        testKat(
            dig, "abcdefghbcdefghicdefghijdefghijkefghijklfghij"
                    + "klmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnop"
                    + "qrsmnopqrstnopqrstu", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                    + "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        )
        println(3)
        testKatMillionA(
            dig, (
                    "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
                            + "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b")
        )
    }
}
