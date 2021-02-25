package com.appmattus.crypto

import fr.cryptohash.Digest
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
