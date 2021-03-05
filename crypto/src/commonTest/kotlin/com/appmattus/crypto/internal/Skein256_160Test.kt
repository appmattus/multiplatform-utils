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
import com.appmattus.crypto.internal.core.sphlib.testKatHex
import com.appmattus.ignore.IgnoreIos
import kotlin.test.AfterTest
import kotlin.test.BeforeTest
import kotlin.test.Test
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.fail

class Skein256_160CoreTest : Skein256_160Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Skein256_160)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class Skein256_160PlatformTest {

    @Test
    fun noImplementation() {
        assertNull(PlatformDigest().create(Algorithm.Skein256_160))
    }
}

// No built-in iOS support
@IgnoreIos
class Skein256_160InstalledProviderTest : Skein256_160Test() {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.Skein256_160) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test Skein-256-160 implementation.
 */
abstract class Skein256_160Test {

    abstract fun digest(): Digest<*>

    // From specification - skein_golden_kat.txt
    @Test
    fun zero() {
        testKat(
            digest(),
            ByteArray(128),
            "2E693AA8CAFB42D90C808F7D2FB6C925DF618275"
        )
    }

    // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/SkeinDigestTest.java
    @Test
    fun testSkein256_160() {
        testKatHex(
            digest(),
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
                    + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
                    + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
                    + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "0cd491b7715704c3a15a45a1ca8d93f8f646d3a1"
        )
    }
}