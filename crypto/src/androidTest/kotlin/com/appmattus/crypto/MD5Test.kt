package com.appmattus.crypto

import fr.cryptohash.Digest
import fr.cryptohash.MD2
import fr.cryptohash.MD4
import fr.cryptohash.MD5
import fr.cryptohash.SHA0
import fr.cryptohash.SHA1
import fr.cryptohash.SHA224
import fr.cryptohash.SHA256
import fr.cryptohash.SHA384
import fr.cryptohash.SHA512
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.fail

class MD5Test {

    @Test
    fun testIt() {
        // Expected
        // d41d8cd98f00b204e9800998ecf8427e

        // Actual
        // 67452301efcdab8998badcfe10325476

        val shlib = MD5().digest()
        println("shlib: " + shlib.asString())

        val emptyDigest = MessageDigest.getInstance("MD5").digest()
        println("msg digest: " + emptyDigest.asString())
    }

    /**
     * Test MD2 implementation.
     */
    @Test
    fun testMD2() {
        val dig: Digest = MD2()
        testKat(dig, "", "8350e5a3e24c153df2275c9f80692773")
        testKat(dig, "a", "32ec01ec4a6dac72c0ab96fb34c0b5d1")
        testKat(dig, "abc", "da853b0d3f88d99b30283a69e6ded6bb")
        testKat(
            dig, "message digest",
            "ab4f496bfb2a530b219ff33031fe06b0"
        )
        testKat(
            dig, "abcdefghijklmnopqrstuvwxyz",
            "4e8ddff3650292ab5a4108c3aa47940b"
        )
        testKat(
            dig, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu"
                    + "vwxyz0123456789",
            "da33def2a42df13975352846c30338cd"
        )
        testKat(
            dig, "1234567890123456789012345678901234567890123456789"
                    + "0123456789012345678901234567890",
            "d5976f79d83d3a0dc9806c3c66f3efd8"
        )
        testKatMillionA(dig, "8c0a09ff1216ecaf95c8130953c62efd")
        reportSuccess("MD2")
    }

    /**
     * Test MD4 implementation.
     */
    @Test
    fun testMD4() {
        val dig: Digest = MD4()
        testKat(dig, "", "31d6cfe0d16ae931b73c59d7e0c089c0")
        testKat(dig, "a", "bde52cb31de33e46245e05fbdbd6fb24")
        testKat(dig, "abc", "a448017aaf21d8525fc10ae87aa6729d")
        testKat(
            dig, "message digest",
            "d9130a8164549fe818874806e1c7014b"
        )
        testKat(
            dig, "abcdefghijklmnopqrstuvwxyz",
            "d79e1c308aa5bbcdeea8ed63df412da9"
        )
        testKat(
            dig, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu"
                    + "vwxyz0123456789",
            "043f8582f241db351ce627e153e7f0e4"
        )
        testKat(
            dig, "1234567890123456789012345678901234567890123456789"
                    + "0123456789012345678901234567890",
            "e33b4ddc9c38f2199c3e7b164fcc0536"
        )
        testKatMillionA(dig, "bbce80cc6bb65e5c6745e30d4eeca9a4")
        testCollision(
            dig,
            "839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20"
                    + "a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba631"
                    + "8edd45e51fe39708bf9427e9c3e8b9",
            ("839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20"
                    + "a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba631"
                    + "8edc45e51fe39708bf9427e9c3e8b9")
        )
        testCollision(
            dig,
            ("839c7a4d7a92cb5678a5d5b9eea5a7573c8a74deb366c3dc20"
                    + "a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba631"
                    + "8edd45e51fe39740c213f769cfb8a7"),
            ("839c7a4d7a92cbd678a5d529eea5a7573c8a74deb366c3dc20"
                    + "a083b69f5d2a3bb3719dc69891e9f95e809fd7e8b23ba631"
                    + "8edc45e51fe39740c213f769cfb8a7")
        )
        reportSuccess("MD4")
    }

    /**
     * Test MD5 implementation.
     */
    @Test
    fun testMD5() {
        val dig: Digest = MD5()
        testKat(dig, "", "d41d8cd98f00b204e9800998ecf8427e")
        testKat(dig, "a", "0cc175b9c0f1b6a831c399e269772661")
        testKat(dig, "abc", "900150983cd24fb0d6963f7d28e17f72")
        testKat(
            dig, "message digest",
            "f96b697d7cb7938d525a2f31aaf161d0"
        )
        testKat(
            dig, "abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b"
        )
        testKat(
            dig, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstu"
                    + "vwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f"
        )
        testKat(
            dig, "1234567890123456789012345678901234567890123456789"
                    + "0123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a"
        )
        testKatMillionA(dig, "7707d6ae4e027c70eea2a935c2296f21")
        testCollision(
            dig,
            "d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab40"
                    + "04583eb8fb7f8955ad340609f4b30283e488832571415a08"
                    + "5125e8f7cdc99fd91dbdf280373c5b960b1dd1dc417b9ce4"
                    + "d897f45a6555d535739ac7f0ebfd0c3029f166d109b18f75"
                    + "277f7930d55ceb22e8adba79cc155ced74cbdd5fc5d36db1"
                    + "9b0ad835cca7e3",
            ("d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab40"
                    + "04583eb8fb7f8955ad340609f4b30283e4888325f1415a08"
                    + "5125e8f7cdc99fd91dbd7280373c5b960b1dd1dc417b9ce4"
                    + "d897f45a6555d535739a47f0ebfd0c3029f166d109b18f75"
                    + "277f7930d55ceb22e8adba794c155ced74cbdd5fc5d36db1"
                    + "9b0a5835cca7e3")
        )
        testCollision(
            dig,
            ("d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab40"
                    + "04583eb8fb7f8955ad340609f4b30283e488832571415a08"
                    + "5125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae"
                    + "6dacd436c919c6dd53e2b487da03fd02396306d248cda0e9"
                    + "9f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396"
                    + "f9652b6ff72a70"),
            ("d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab40"
                    + "04583eb8fb7f8955ad340609f4b30283e4888325f1415a08"
                    + "5125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae"
                    + "6dacd436c919c6dd53e23487da03fd02396306d248cda0e9"
                    + "9f33420f577ee8ce54b67080280d1ec69821bcb6a8839396"
                    + "f965ab6ff72a70")
        )
        reportSuccess("MD5")
    }

    /**
     * Test SHA-0 implementation.
     */
    @Test
    fun testSHA0() {
        val dig: Digest = SHA0()
        testKat(dig, "abc", "0164b8a914cd2a5e74c4f7ff082c4d97f1edf880")
        testKat(
            dig, "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlm"
                    + "nomnopnopq",
            "d2516ee1acfa5baf33dfc1c471e438449ef134c8"
        )
        testKatMillionA(
            dig,
            "3232affa48628a26653b5aaa44541fd90d690603"
        )
        testCollision(
            dig,
            "a766a602b65cffe773bcf25826b322b3d01b1a972684ef533e"
                    + "3b4b7f53fe376224c08e47e959b2bc3b519880b928656824"
                    + "7d110f70f5c5e2b4590ca3f55f52feeffd4c8fe68de83532"
                    + "9e603cc51e7f02545410d1671d108df5a4000dcf20a43949"
                    + "49d72cd14fbb0345cf3a295dcda89f998f87552c9a58b1bd"
                    + "c384835e477185f96e68bebb0025d2d2b69edf21724198f6"
                    + "88b41deb9b4913fbe696b5457ab39921e1d7591f89de8457"
                    + "e8613c6c9e3b242879d4d8783b2d9ca9935ea526a729c06e"
                    + "dfc50137e69330be976012cc5dfe1c14c4c68bd1db3ecb24"
                    + "438a59a09b5db435563e0d8bdf572f77b53065cef31f32dc"
                    + "9dbaa04146261e9994bd5cd0758e3d",
            ("a766a602b65cffe773bcf25826b322b1d01b1ad72684ef51be"
                    + "3b4b7fd3fe3762a4c08e45e959b2fc3b51988039286528a4"
                    + "7d110d70f5c5e034590ce3755f52fc6ffd4c8d668de87532"
                    + "9e603e451e7f02d45410d1e71d108df5a4000dcf20a43949"
                    + "49d72cd14fbb0145cf3a695dcda89d198f8755ac9a58b13d"
                    + "c384815e4771c5796e68febb0025d052b69edda17241d876"
                    + "88b41f6b9b49117be696f5c57ab399a1e1d7199f89de8657"
                    + "e8613cec9e3b26a879d498783b2d9e29935ea7a6a729806e"
                    + "dfc50337e693303e9760104c5dfe5c14c4c68951db3ecba4"
                    + "438a59209b5db435563e0d8bdf572f77b53065cef31f30dc"
                    + "9dbae04146261c1994bd5c50758e3d")
        )
        reportSuccess("SHA-0")
    }

    /**
     * Test SHA-1 implementation.
     */
    @Test
    fun testSHA1() {
        val dig: Digest = SHA1()
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
        reportSuccess("SHA-1")
    }

    /**
     * Test SHA-224 implementation.
     */
    @Test
    fun testSHA224() {
        val dig: Digest = SHA224()
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
        reportSuccess("SHA-224")
    }

    /**
     * Test SHA-256 implementation.
     */
    @Test
    fun testSHA256() {
        val dig: Digest = SHA256()
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
        reportSuccess("SHA-256")
    }

    /**
     * Test SHA-384 implementation.
     */
    @Test
    fun testSHA384() {
        val dig: Digest = SHA384()
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
        reportSuccess("SHA-384")
    }

    /**
     * Test SHA-512 implementation.
     */
    @Test
    fun testSHA512() {
        val dig: Digest = SHA512()
        testKat(
            dig, "abc", "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
                    + "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
        )
        testKat(
            dig, "abcdefghbcdefghicdefghijdefghijkefghijklfghij"
                    + "klmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnop"
                    + "qrsmnopqrstnopqrstu", "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018"
                    + "501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909"
        )
        testKatMillionA(
            dig, (
                    "e718483d0ce769644e2e42c7bc15b4638e1f98b13b2044285632a803afa973eb"
                            + "de0ff244877ea60a4cb0432ce577c31beb009c5c2c49aa2e4eadb217ad8cc09b")
        )
        reportSuccess("SHA-512")
    }

    private fun reportSuccess(name: String) {
        println("===== test $name passed")
    }

    private fun testKat(dig: Digest, buf: ByteArray, exp: ByteArray) {
        /*
		 * First test the hashing itself.
		 */
        val out = dig.digest(buf)
        assertEquals(out, exp)

        /*
		 * Now the update() API; this also exercises auto-reset.
		 */for (i in buf.indices) dig.update(buf[i])
        assertEquals(dig.digest(), exp)

        /*
		 * The cloning API.
		 */
        val blen = buf.size
        dig.update(buf, 0, blen / 2)
        val dig2 = dig.copy()
        dig.update(buf, blen / 2, blen - blen / 2)
        assertEquals(dig.digest(), exp)
        dig2!!.update(buf, blen / 2, blen - blen / 2)
        assertEquals(dig2.digest(), exp)
    }

    private fun testKat(dig: Digest, data: String, ref: String) {
        testKat(dig, encodeLatin1(data), strtobin(ref))
    }

    private fun testKatHex(dig: Digest, data: String, ref: String) {
        testKat(dig, strtobin(data), strtobin(ref))
    }

    private fun testKatMillionA(dig: Digest, ref: String) {
        val buf = ByteArray(1000)
        for (i in 0..999) buf[i] = 'a'.toByte()
        for (i in 0..999) dig.update(buf)
        assertEquals(dig.digest(), strtobin(ref))
    }

    private fun testCollision(dig: Digest, s1: String, s2: String) {
        val msg1 = strtobin(s1)
        val msg2 = strtobin(s2)
        assertNotEquals(msg1, msg2)
        assertEquals(dig.digest(msg1), dig.digest(msg2))
    }

    private fun strtobin(str: String): ByteArray {
        val blen = str.length / 2
        val buf = ByteArray(blen)
        for (i in 0 until blen) {
            val bs = str.substring(i * 2, i * 2 + 2)
            buf[i] = bs.toInt(16).toByte()
        }
        return buf
    }

    private fun encodeLatin1(str: String): ByteArray {
        val blen = str.length
        val buf = ByteArray(blen)
        for (i in 0 until blen) buf[i] = str[i].toByte()
        return buf
    }

    private fun equals(b1: ByteArray?, b2: ByteArray?): Boolean {
        if (b1 == b2) return true
        if (b1 == null || b2 == null) return false
        if (b1.size != b2.size) return false
        for (i in b1.indices) if (b1[i] != b2[i]) return false
        return true
    }

    private fun assertTrue(expr: Boolean) {
        if (!expr) fail("assertion failed")
    }

    private fun assertEquals(b1: ByteArray, b2: ByteArray) {
        if (!equals(b1, b2)) fail("byte streams are not equal")
    }

    private fun assertNotEquals(b1: ByteArray, b2: ByteArray) {
        if (equals(b1, b2)) fail("byte streams are equal")
    }
}

fun ByteArray.asString(): String = joinToString("") {
    (0xFF and it.toInt()).toString(16).padStart(2, '0')
}
