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

@file:Suppress("ClassName")

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.sphlib.testKat
import com.appmattus.crypto.internal.core.sphlib.testKatMillionA
import com.appmattus.ignore.IgnoreIos
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.fail

class GOST3411CoreTest : GOST3411Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.GOST3411_94)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

// No built-in support
class GOST3411PlatformTest {

    @Test
    fun noImplementation() {
        assertNull(PlatformDigest().create(Algorithm.GOST3411_94))
    }
}

// No built-in iOS support
@IgnoreIos
class GOST3411InstalledProviderTest : GOST3411Test() {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.GOST3411_94) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test GOST3411 implementation.
 */
abstract class GOST3411Test {

    abstract fun digest(): Digest<*>

    @Test
    fun empty() {
        testKat(
            digest(),
            "",
            "981e5f3ca30c841487830f84fb433e13ac1101569b9c13584ac483234cd656c0"
        )
    }

    @Test
    fun thirtyTwoBytes() {
        testKat(
            digest(),
            "This is message, length=32 bytes",
            "2cefc2f7b7bdc514e18ea57fa74ff357e7fa17d652c75f69cb1be7893ede48eb"
        )
    }

    @Test
    fun fiftyBytes() {
        testKat(
            digest(),
            "Suppose the original message has length = 50 bytes",
            "c3730c5cbccacf915ac292676f21e8bd4ef75331d9405e5f1a61dc3130a65011"
        )
    }

    @Test
    fun alphabetAndNumbers() {
        testKat(
            digest(),
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "73b70a39497de53a6e08c67b6d4db853540f03e9389299d9b0156ef7e85d0f61"
        )
    }

    @Test
    fun millionA() {
        testKatMillionA(
            digest(),
            "8693287aa62f9478f7cb312ec0866b6c4e4a0f11160441e8f4ffcd2715dd554f"
        )
    }
}
