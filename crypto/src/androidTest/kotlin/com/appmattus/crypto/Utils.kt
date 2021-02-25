package com.appmattus.crypto

import fr.cryptohash.Digest
import kotlin.test.fail

fun reportSuccess(name: String) {
    println("===== test $name passed")
}

fun testKat(dig: Digest, buf: ByteArray, exp: ByteArray) {
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
    dig2.update(buf, blen / 2, blen - blen / 2)
    assertEquals(dig2.digest(), exp)
}

fun testKat(dig: Digest, data: String, ref: String) {
    testKat(dig, encodeLatin1(data), strtobin(ref))
}

fun testKatHex(dig: Digest, data: String, ref: String) {
    testKat(dig, strtobin(data), strtobin(ref))
}

fun testKatMillionA(dig: Digest, ref: String) {
    val buf = ByteArray(1000)
    for (i in 0..999) buf[i] = 'a'.toByte()
    for (i in 0..999) dig.update(buf)
    assertEquals(dig.digest(), strtobin(ref))
}

fun testCollision(dig: Digest, s1: String, s2: String) {
    val msg1 = strtobin(s1)
    val msg2 = strtobin(s2)
    assertNotEquals(msg1, msg2)
    assertEquals(dig.digest(msg1), dig.digest(msg2))
}

fun strtobin(str: String): ByteArray {
    val blen = str.length / 2
    val buf = ByteArray(blen)
    for (i in 0 until blen) {
        val bs = str.substring(i * 2, i * 2 + 2)
        buf[i] = bs.toInt(16).toByte()
    }
    return buf
}

fun encodeLatin1(str: String): ByteArray {
    val blen = str.length
    val buf = ByteArray(blen)
    for (i in 0 until blen) buf[i] = str[i].toByte()
    return buf
}

fun equals(b1: ByteArray?, b2: ByteArray?): Boolean {
    return b1.contentEquals(b2)
    /*if (b1 == b2) return true
    if (b1 == null || b2 == null) return false
    if (b1.size != b2.size) return false
    for (i in b1.indices) if (b1[i] != b2[i]) return false
    return true*/
}

fun assertTrue(expr: Boolean) {
    if (!expr) fail("assertion failed")
}

fun assertEquals(b1: ByteArray, b2: ByteArray) {
    if (!equals(b1, b2)) fail("byte streams are not equal")
}

fun assertNotEquals(b1: ByteArray, b2: ByteArray) {
    if (equals(b1, b2)) fail("byte streams are equal")
}
