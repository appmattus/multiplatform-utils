// $Id: RIPEMD160.java 214 2010-06-03 17:25:08Z tp $
package fr.cryptohash

/**
 *
 * This class implements the RIPEMD-160 digest algorithm under the
 * [Digest] API.
 *
 * <pre>
 * ==========================(LICENSE BEGIN)============================
 *
 * Copyright (c) 2007-2010  Projet RNRT SAPHIR
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * ===========================(LICENSE END)=============================
</pre> *
 *
 * @version   $Revision: 214 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class RIPEMD160
/**
 * Build the object.
 */
    : MDHelper(true, 8) {
    private lateinit var currentVal: IntArray
    private lateinit var X: IntArray

    /** @see Digest
     */
    override fun copy(): Digest {
        val d = RIPEMD160()
        currentVal.copyInto(d.currentVal, 0, 0, currentVal.size)
        return copyState(d)
    }

    /** @see Digest
     */
    override val digestLength: Int
        get() = 20

    /** @see Digest
     */
    override val blockLength: Int
        get() = 64

    /** @see DigestEngine
     */
    override fun engineReset() {
        currentVal[0] = 0x67452301
        currentVal[1] = -0x10325477
        currentVal[2] = -0x67452302
        currentVal[3] = 0x10325476
        currentVal[4] = -0x3c2d1e10
    }

    /** @see DigestEngine
     */
    override fun doPadding(output: ByteArray, outputOffset: Int) {
        makeMDPadding()
        for (i in 0..4) encodeLEInt(
            currentVal[i],
            output, outputOffset + 4 * i
        )
    }

    /** @see DigestEngine
     */
    override fun doInit() {
        currentVal = IntArray(5)
        X = IntArray(16)
        engineReset()
    }

    /** @see DigestEngine
     */
    override fun processBlock(data: ByteArray) {
        val H0: Int
        val H1: Int
        val H2: Int
        val H3: Int
        val H4: Int
        var A1: Int
        var B1: Int
        var C1: Int
        var D1: Int
        var E1: Int
        var A2: Int
        var B2: Int
        var C2: Int
        var D2: Int
        var E2: Int
        A2 = currentVal[0]
        A1 = A2
        H0 = A1
        B2 = currentVal[1]
        B1 = B2
        H1 = B1
        C2 = currentVal[2]
        C1 = C2
        H2 = C1
        D2 = currentVal[3]
        D1 = D2
        H3 = D1
        E2 = currentVal[4]
        E1 = E2
        H4 = E1
        run {
            var i = 0
            var j = 0
            while (i < 16) {
                X[i] = decodeLEInt(data, j)
                i++
                j += 4
            }
        }
        for (i in 0..15) {
            var T1 = (A1 + (B1 xor C1 xor D1)
                    + X[i])
            T1 = (T1 shl s1[i] or (T1 ushr 32 - s1[i])) + E1
            A1 = E1
            E1 = D1
            D1 = C1 shl 10 or (C1 ushr 22)
            C1 = B1
            B1 = T1
        }
        for (i in 16..31) {
            var T1 = (A1 + (C1 xor D1 and B1 xor D1)
                    + X[r1[i]] + 0x5A827999)
            T1 = (T1 shl s1[i] or (T1 ushr 32 - s1[i])) + E1
            A1 = E1
            E1 = D1
            D1 = C1 shl 10 or (C1 ushr 22)
            C1 = B1
            B1 = T1
        }
        for (i in 32..47) {
            var T1 = (A1 + (B1 or C1.inv() xor D1)
                    + X[r1[i]] + 0x6ED9EBA1)
            T1 = (T1 shl s1[i] or (T1 ushr 32 - s1[i])) + E1
            A1 = E1
            E1 = D1
            D1 = C1 shl 10 or (C1 ushr 22)
            C1 = B1
            B1 = T1
        }
        for (i in 48..63) {
            var T1 = (A1 + (B1 xor C1 and D1 xor C1)
                    + X[r1[i]] + -0x70e44324)
            T1 = (T1 shl s1[i] or (T1 ushr 32 - s1[i])) + E1
            A1 = E1
            E1 = D1
            D1 = C1 shl 10 or (C1 ushr 22)
            C1 = B1
            B1 = T1
        }
        for (i in 64..79) {
            var T1 = (A1 + (B1 xor (C1 or D1.inv()))
                    + X[r1[i]] + -0x56ac02b2)
            T1 = (T1 shl s1[i] or (T1 ushr 32 - s1[i])) + E1
            A1 = E1
            E1 = D1
            D1 = C1 shl 10 or (C1 ushr 22)
            C1 = B1
            B1 = T1
        }
        for (i in 0..15) {
            var T2 = (A2 + (B2 xor (C2 or D2.inv()))
                    + X[r2[i]] + 0x50A28BE6)
            T2 = (T2 shl s2[i] or (T2 ushr 32 - s2[i])) + E2
            A2 = E2
            E2 = D2
            D2 = C2 shl 10 or (C2 ushr 22)
            C2 = B2
            B2 = T2
        }
        for (i in 16..31) {
            var T2 = (A2 + (B2 xor C2 and D2 xor C2)
                    + X[r2[i]] + 0x5C4DD124)
            T2 = (T2 shl s2[i] or (T2 ushr 32 - s2[i])) + E2
            A2 = E2
            E2 = D2
            D2 = C2 shl 10 or (C2 ushr 22)
            C2 = B2
            B2 = T2
        }
        for (i in 32..47) {
            var T2 = (A2 + (B2 or C2.inv() xor D2)
                    + X[r2[i]] + 0x6D703EF3)
            T2 = (T2 shl s2[i] or (T2 ushr 32 - s2[i])) + E2
            A2 = E2
            E2 = D2
            D2 = C2 shl 10 or (C2 ushr 22)
            C2 = B2
            B2 = T2
        }
        for (i in 48..63) {
            var T2 = (A2 + (C2 xor D2 and B2 xor D2)
                    + X[r2[i]] + 0x7A6D76E9)
            T2 = (T2 shl s2[i] or (T2 ushr 32 - s2[i])) + E2
            A2 = E2
            E2 = D2
            D2 = C2 shl 10 or (C2 ushr 22)
            C2 = B2
            B2 = T2
        }
        for (i in 64..79) {
            var T2 = (A2 + (B2 xor C2 xor D2)
                    + X[r2[i]])
            T2 = (T2 shl s2[i] or (T2 ushr 32 - s2[i])) + E2
            A2 = E2
            E2 = D2
            D2 = C2 shl 10 or (C2 ushr 22)
            C2 = B2
            B2 = T2
        }
        val T = H1 + C1 + D2
        currentVal[1] = H2 + D1 + E2
        currentVal[2] = H3 + E1 + A2
        currentVal[3] = H4 + A1 + B2
        currentVal[4] = H0 + B1 + C2
        currentVal[0] = T
    }

    /** @see Digest
     */
    override fun toString(): String {
        return "RIPEMD-160"
    }

    companion object {
        /**
         * Encode the 32-bit word `val` into the array
         * `buf` at offset `off`, in little-endian
         * convention (least significant byte first).
         *
         * @param val   the value to encode
         * @param buf   the destination buffer
         * @param off   the destination offset
         */
        private fun encodeLEInt(`val`: Int, buf: ByteArray, off: Int) {
            buf[off + 0] = `val`.toByte()
            buf[off + 1] = (`val` ushr 8).toByte()
            buf[off + 2] = (`val` ushr 16).toByte()
            buf[off + 3] = (`val` ushr 24).toByte()
        }

        /**
         * Decode a 32-bit little-endian word from the array `buf`
         * at offset `off`.
         *
         * @param buf   the source buffer
         * @param off   the source offset
         * @return  the decoded value
         */
        private fun decodeLEInt(buf: ByteArray, off: Int): Int {
            return (buf[off + 0].toInt() and 0xFF
                    or (buf[off + 1].toInt() and 0xFF shl 8)
                    or (buf[off + 2].toInt() and 0xFF shl 16)
                    or (buf[off + 3].toInt() and 0xFF shl 24))
        }

        /**
         * Perform a circular rotation by `n` to the left
         * of the 32-bit word `x`. The `n` parameter
         * must lie between 1 and 31 (inclusive).
         *
         * @param x   the value to rotate
         * @param n   the rotation count (between 1 and 31)
         * @return  the rotated value
         */
        private fun circularLeft(x: Int, n: Int): Int {
            return x shl n or (x ushr 32 - n)
        }

        private val r1 = intArrayOf(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
            4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
        )
        private val r2 = intArrayOf(
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
            12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
        )
        private val s1 = intArrayOf(
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
            9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
        )
        private val s2 = intArrayOf(
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
            8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
        )
    }
}
