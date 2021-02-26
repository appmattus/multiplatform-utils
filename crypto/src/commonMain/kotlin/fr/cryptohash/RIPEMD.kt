// $Id: RIPEMD.java 214 2010-06-03 17:25:08Z tp $
package fr.cryptohash

/**
 *
 * This class implements the RIPEMD digest algorithm under the [ ] API. This is the original RIPEMD, **not** the
 * strengthened variants RIPEMD-128 or RIPEMD-160. A collision for this
 * RIPEMD has been published in 2004.
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
/*
 * TODO: merge some of this code with that of RIPEMD128.
 */
class RIPEMD : MDHelper(true, 8) {

    private lateinit var currentVal: IntArray
    private lateinit var X: IntArray

    override fun copy(): Digest {
        val d = RIPEMD()
        currentVal.copyInto(d.currentVal, 0, 0, currentVal.size)
        return copyState(d)
    }

    override val digestLength: Int
        get() = 16

    override val blockLength: Int
        get() = 64

    override fun engineReset() {
        currentVal[0] = 0x67452301
        currentVal[1] = -0x10325477
        currentVal[2] = -0x67452302
        currentVal[3] = 0x10325476
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        makeMDPadding()
        for (i in 0..3) encodeLEInt(
            currentVal[i],
            output, outputOffset + 4 * i
        )
    }

    override fun doInit() {
        currentVal = IntArray(4)
        X = IntArray(16)
        engineReset()
    }

    override fun processBlock(data: ByteArray) {
        val H0: Int
        val H1: Int
        val H2: Int
        val H3: Int
        var A1: Int
        var B1: Int
        var C1: Int
        var D1: Int
        var A2: Int
        var B2: Int
        var C2: Int
        var D2: Int
        var tmp: Int
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
        var i = 0
        var j = 0
        while (i < 16) {
            X[i] = decodeLEInt(data, j)
            i++
            j += 4
        }
        tmp = A1 + (C1 xor D1 and B1 xor D1) + X[0]
        A1 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = D1 + (B1 xor C1 and A1 xor C1) + X[1]
        D1 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = C1 + (A1 xor B1 and D1 xor B1) + X[2]
        C1 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = B1 + (D1 xor A1 and C1 xor A1) + X[3]
        B1 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = A1 + (C1 xor D1 and B1 xor D1) + X[4]
        A1 = tmp shl 5 or (tmp ushr 32 - 5)
        tmp = D1 + (B1 xor C1 and A1 xor C1) + X[5]
        D1 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = C1 + (A1 xor B1 and D1 xor B1) + X[6]
        C1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = B1 + (D1 xor A1 and C1 xor A1) + X[7]
        B1 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = A1 + (C1 xor D1 and B1 xor D1) + X[8]
        A1 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = D1 + (B1 xor C1 and A1 xor C1) + X[9]
        D1 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = C1 + (A1 xor B1 and D1 xor B1) + X[10]
        C1 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = B1 + (D1 xor A1 and C1 xor A1) + X[11]
        B1 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = A1 + (C1 xor D1 and B1 xor D1) + X[12]
        A1 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = D1 + (B1 xor C1 and A1 xor C1) + X[13]
        D1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = C1 + (A1 xor B1 and D1 xor B1) + X[14]
        C1 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = B1 + (D1 xor A1 and C1 xor A1) + X[15]
        B1 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = A1 + (B1 and C1 or (B1 or C1 and D1)) + X[7] + 0x5A827999
        A1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = D1 + (A1 and B1 or (A1 or B1 and C1)) + X[4] + 0x5A827999
        D1 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = C1 + (D1 and A1 or (D1 or A1 and B1)) + X[13] + 0x5A827999
        C1 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = B1 + (C1 and D1 or (C1 or D1 and A1)) + X[1] + 0x5A827999
        B1 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = A1 + (B1 and C1 or (B1 or C1 and D1)) + X[10] + 0x5A827999
        A1 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = D1 + (A1 and B1 or (A1 or B1 and C1)) + X[6] + 0x5A827999
        D1 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = C1 + (D1 and A1 or (D1 or A1 and B1)) + X[15] + 0x5A827999
        C1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = B1 + (C1 and D1 or (C1 or D1 and A1)) + X[3] + 0x5A827999
        B1 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = A1 + (B1 and C1 or (B1 or C1 and D1)) + X[12] + 0x5A827999
        A1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = D1 + (A1 and B1 or (A1 or B1 and C1)) + X[0] + 0x5A827999
        D1 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = C1 + (D1 and A1 or (D1 or A1 and B1)) + X[9] + 0x5A827999
        C1 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = B1 + (C1 and D1 or (C1 or D1 and A1)) + X[5] + 0x5A827999
        B1 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = A1 + (B1 and C1 or (B1 or C1 and D1)) + X[14] + 0x5A827999
        A1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = D1 + (A1 and B1 or (A1 or B1 and C1)) + X[2] + 0x5A827999
        D1 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = C1 + (D1 and A1 or (D1 or A1 and B1)) + X[11] + 0x5A827999
        C1 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = B1 + (C1 and D1 or (C1 or D1 and A1)) + X[8] + 0x5A827999
        B1 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = A1 + (B1 xor C1 xor D1) + X[3] + 0x6ED9EBA1
        A1 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = D1 + (A1 xor B1 xor C1) + X[10] + 0x6ED9EBA1
        D1 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = C1 + (D1 xor A1 xor B1) + X[2] + 0x6ED9EBA1
        C1 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = B1 + (C1 xor D1 xor A1) + X[4] + 0x6ED9EBA1
        B1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = A1 + (B1 xor C1 xor D1) + X[9] + 0x6ED9EBA1
        A1 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = D1 + (A1 xor B1 xor C1) + X[15] + 0x6ED9EBA1
        D1 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = C1 + (D1 xor A1 xor B1) + X[8] + 0x6ED9EBA1
        C1 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = B1 + (C1 xor D1 xor A1) + X[1] + 0x6ED9EBA1
        B1 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = A1 + (B1 xor C1 xor D1) + X[14] + 0x6ED9EBA1
        A1 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = D1 + (A1 xor B1 xor C1) + X[7] + 0x6ED9EBA1
        D1 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = C1 + (D1 xor A1 xor B1) + X[0] + 0x6ED9EBA1
        C1 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = B1 + (C1 xor D1 xor A1) + X[6] + 0x6ED9EBA1
        B1 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = A1 + (B1 xor C1 xor D1) + X[11] + 0x6ED9EBA1
        A1 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = D1 + (A1 xor B1 xor C1) + X[13] + 0x6ED9EBA1
        D1 = tmp shl 5 or (tmp ushr 32 - 5)
        tmp = C1 + (D1 xor A1 xor B1) + X[5] + 0x6ED9EBA1
        C1 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = B1 + (C1 xor D1 xor A1) + X[12] + 0x6ED9EBA1
        B1 = tmp shl 5 or (tmp ushr 32 - 5)
        tmp = A2 + (C2 xor D2 and B2 xor D2) + X[0] + 0x50A28BE6
        A2 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = D2 + (B2 xor C2 and A2 xor C2) + X[1] + 0x50A28BE6
        D2 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = C2 + (A2 xor B2 and D2 xor B2) + X[2] + 0x50A28BE6
        C2 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = B2 + (D2 xor A2 and C2 xor A2) + X[3] + 0x50A28BE6
        B2 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = A2 + (C2 xor D2 and B2 xor D2) + X[4] + 0x50A28BE6
        A2 = tmp shl 5 or (tmp ushr 32 - 5)
        tmp = D2 + (B2 xor C2 and A2 xor C2) + X[5] + 0x50A28BE6
        D2 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = C2 + (A2 xor B2 and D2 xor B2) + X[6] + 0x50A28BE6
        C2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = B2 + (D2 xor A2 and C2 xor A2) + X[7] + 0x50A28BE6
        B2 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = A2 + (C2 xor D2 and B2 xor D2) + X[8] + 0x50A28BE6
        A2 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = D2 + (B2 xor C2 and A2 xor C2) + X[9] + 0x50A28BE6
        D2 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = C2 + (A2 xor B2 and D2 xor B2) + X[10] + 0x50A28BE6
        C2 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = B2 + (D2 xor A2 and C2 xor A2) + X[11] + 0x50A28BE6
        B2 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = A2 + (C2 xor D2 and B2 xor D2) + X[12] + 0x50A28BE6
        A2 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = D2 + (B2 xor C2 and A2 xor C2) + X[13] + 0x50A28BE6
        D2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = C2 + (A2 xor B2 and D2 xor B2) + X[14] + 0x50A28BE6
        C2 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = B2 + (D2 xor A2 and C2 xor A2) + X[15] + 0x50A28BE6
        B2 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = A2 + (B2 and C2 or (B2 or C2 and D2)) + X[7]
        A2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = D2 + (A2 and B2 or (A2 or B2 and C2)) + X[4]
        D2 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = C2 + (D2 and A2 or (D2 or A2 and B2)) + X[13]
        C2 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = B2 + (C2 and D2 or (C2 or D2 and A2)) + X[1]
        B2 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = A2 + (B2 and C2 or (B2 or C2 and D2)) + X[10]
        A2 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = D2 + (A2 and B2 or (A2 or B2 and C2)) + X[6]
        D2 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = C2 + (D2 and A2 or (D2 or A2 and B2)) + X[15]
        C2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = B2 + (C2 and D2 or (C2 or D2 and A2)) + X[3]
        B2 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = A2 + (B2 and C2 or (B2 or C2 and D2)) + X[12]
        A2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = D2 + (A2 and B2 or (A2 or B2 and C2)) + X[0]
        D2 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = C2 + (D2 and A2 or (D2 or A2 and B2)) + X[9]
        C2 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = B2 + (C2 and D2 or (C2 or D2 and A2)) + X[5]
        B2 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = A2 + (B2 and C2 or (B2 or C2 and D2)) + X[14]
        A2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = D2 + (A2 and B2 or (A2 or B2 and C2)) + X[2]
        D2 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = C2 + (D2 and A2 or (D2 or A2 and B2)) + X[11]
        C2 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = B2 + (C2 and D2 or (C2 or D2 and A2)) + X[8]
        B2 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = A2 + (B2 xor C2 xor D2) + X[3] + 0x5C4DD124
        A2 = tmp shl 11 or (tmp ushr 32 - 11)
        tmp = D2 + (A2 xor B2 xor C2) + X[10] + 0x5C4DD124
        D2 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = C2 + (D2 xor A2 xor B2) + X[2] + 0x5C4DD124
        C2 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = B2 + (C2 xor D2 xor A2) + X[4] + 0x5C4DD124
        B2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = A2 + (B2 xor C2 xor D2) + X[9] + 0x5C4DD124
        A2 = tmp shl 14 or (tmp ushr 32 - 14)
        tmp = D2 + (A2 xor B2 xor C2) + X[15] + 0x5C4DD124
        D2 = tmp shl 9 or (tmp ushr 32 - 9)
        tmp = C2 + (D2 xor A2 xor B2) + X[8] + 0x5C4DD124
        C2 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = B2 + (C2 xor D2 xor A2) + X[1] + 0x5C4DD124
        B2 = tmp shl 15 or (tmp ushr 32 - 15)
        tmp = A2 + (B2 xor C2 xor D2) + X[14] + 0x5C4DD124
        A2 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = D2 + (A2 xor B2 xor C2) + X[7] + 0x5C4DD124
        D2 = tmp shl 8 or (tmp ushr 32 - 8)
        tmp = C2 + (D2 xor A2 xor B2) + X[0] + 0x5C4DD124
        C2 = tmp shl 13 or (tmp ushr 32 - 13)
        tmp = B2 + (C2 xor D2 xor A2) + X[6] + 0x5C4DD124
        B2 = tmp shl 6 or (tmp ushr 32 - 6)
        tmp = A2 + (B2 xor C2 xor D2) + X[11] + 0x5C4DD124
        A2 = tmp shl 12 or (tmp ushr 32 - 12)
        tmp = D2 + (A2 xor B2 xor C2) + X[13] + 0x5C4DD124
        D2 = tmp shl 5 or (tmp ushr 32 - 5)
        tmp = C2 + (D2 xor A2 xor B2) + X[5] + 0x5C4DD124
        C2 = tmp shl 7 or (tmp ushr 32 - 7)
        tmp = B2 + (C2 xor D2 xor A2) + X[12] + 0x5C4DD124
        B2 = tmp shl 5 or (tmp ushr 32 - 5)
        val T = H1 + C1 + D2
        currentVal[1] = H2 + D1 + A2
        currentVal[2] = H3 + A1 + B2
        currentVal[3] = H0 + B1 + C2
        currentVal[0] = T
    }

    override fun toString(): String {
        return "RIPEMD"
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
    }
}
