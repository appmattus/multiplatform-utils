package com.appmattus.crypto

import fr.cryptohash.SHA224
import fr.cryptohash.SHA256
import kotlin.test.Test

class SHA2CoreTest {

    /**
     * Test SHA-224 implementation.
     */
    @Test
    fun testSHA224() {
        val dig = SHA224()
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

    /**
     * Test SHA-256 implementation.
     */
    @Test
    fun testSHA256() {
        val dig = SHA256()
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
