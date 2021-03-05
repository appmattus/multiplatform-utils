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

class Skein256_256CoreTest : Skein256_256Test() {
    override fun digest(): Digest<*> = CoreDigest.create(Algorithm.Skein256_256)

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

class Skein256_256PlatformTest {

    @Test
    fun noImplementation() {
        assertNull(PlatformDigest().create(Algorithm.Skein256_256))
    }
}

// No built-in iOS support
@IgnoreIos
class Skein256_256InstalledProviderTest : Skein256_256Test() {

    @BeforeTest
    fun beforeTest() {
        installPlatformProvider()
    }

    @AfterTest
    fun afterTest() {
        removePlatformProvider()
    }

    override fun digest(): Digest<*> = PlatformDigest().create(Algorithm.Skein256_256) ?: fail()

    @Test
    fun hasImplementation() {
        assertNotNull(digest())
    }
}

/**
 * Test Skein-256-256 implementation.
 */
abstract class Skein256_256Test {

    abstract fun digest(): Digest<*>

    @Test
    fun zero() {
        testKat(
            digest(),
            ByteArray(1),
            "34E2B65BF0BE667CA5DEBA82C37CB253EB9F8474F3426BA622A25219FD182433"
        )
        testKat(
            digest(),
            ByteArray(24),
            "CBC26DE4C8212B6C7BC4E0CA43790A55FB19A6E47C64A77D8F8FB324DB126841"
        )
        testKat(
            digest(),
            ByteArray(32),
            "0FED47EF57B61379E4A406A8FA3F8FB9D380DAFADA318FF1491D1108D6600A50"
        )
        testKat(
            digest(),
            ByteArray(48),
            "FBF567B14234F140C06454EB26B83968DF8A8CFCCE69AFDE33A232EB2226137C"
        )
        testKat(
            digest(),
            ByteArray(64),
            "3E0CA29E4863E8BE4D9F28777A7FDC676032C4D9F6904B1CB6AABB029F33741A"
        )
    }

    // From https://github.com/bcgit/bc-java/blob/master/core/src/test/java/org/bouncycastle/crypto/test/SkeinDigestTest.java
    @Test
    fun testSkein256_256() {
        testKatHex(
            digest(),
            "",
            "c8877087da56e072870daa843f176e9453115929094c3a40c463a196c29bf7ba"
        )
        testKatHex(
            digest(),
            "fb",
            "088eb23cc2bccfb8171aa64e966d4af937325167dfcd170700ffd21f8a4cbdac"
        )
        testKatHex(
            digest(),
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8",
            "5c3002ff57a627089ea2f97a5000d5678416389019e80e45a3bbcab118315d26"
        )
        testKatHex(
            digest(),
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc878bb393a1a5f79bef30995a85a129233",
            "640c894a4bba6574c83e920ddf7dd2982fc634881bbbcb9d774eae0a285e89ce"
        )
        testKatHex(
            digest(),
            "fbd17c26b61a82e12e125f0d459b96c91ab4837dff22b39b78439430cdfc5dc8"
                    + "78bb393a1a5f79bef30995a85a12923339ba8ab7d8fc6dc5fec6f4ed22c122bb"
                    + "e7eb61981892966de5cef576f71fc7a80d14dab2d0c03940b95b9fb3a727c66a"
                    + "6e1ff0dc311b9aa21a3054484802154c1826c2a27a0914152aeb76f1168d4410",
            "4de6fe2bfdaa3717a4261030ef0e044ced9225d066354610842a24a3eafd1dcf"
        )
    }

    // From specification - skein_golden_kat_short.txt
    @Test
    fun goldenKatShort() {
        testKatHex(
            digest(),
            "FF",
            "0B98DCD198EA0E50A7A244C444E25C23" +
                    "DA30C10FC9A1F270A6637F1F34E67ED2"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0",
            "8D0FA4EF777FD759DFD4044E6F6A5AC3" +
                    "C774AEC943DCFC07927B723B5DBF408B"
        )
        testKatHex(
            digest(),
            "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0" +
                    "EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" +
                    "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0" +
                    "CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0",
            "DF28E916630D0B44C4A849DC9A02F07A" +
                    "07CB30F732318256B15D865AC4AE162F"
        )
    }
}
