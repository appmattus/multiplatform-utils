package fr.cryptohash

import kotlin.test.Test

class SHA1Test {

    /**
     * Test SHA-1 implementation.
     */
    @Test
    fun testSHA1() {
        val dig = SHA1()
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
