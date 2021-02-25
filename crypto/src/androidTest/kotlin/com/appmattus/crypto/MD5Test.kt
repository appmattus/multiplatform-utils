package com.appmattus.crypto

import fr.cryptohash.Digest
import fr.cryptohash.MD2
import fr.cryptohash.MD4
import fr.cryptohash.MD5
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
