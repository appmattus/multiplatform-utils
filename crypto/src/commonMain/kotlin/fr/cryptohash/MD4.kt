// $Id: MD4.java 241 2010-06-21 15:04:01Z tp $
package fr.cryptohash

/**
 *
 * This class implements the MD4 digest algorithm under the
 * [Digest] API, using the [DigestEngine] class.
 * MD4 is described in RFC 1320.
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
 * @version   $Revision: 241 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class MD4 : MDHelper(true, 8) {

    private lateinit var currentVal: IntArray

    override fun copy(): Digest {
        val d = MD4()
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
            currentVal[i], output,
            outputOffset + 4 * i
        )
    }

    override fun doInit() {
        currentVal = IntArray(4)
        engineReset()
    }

    override fun processBlock(data: ByteArray) {
        /*
		 * This method could have been made simpler by using
		 * external methods for 32-bit decoding, or the round
		 * functions F, G and H. However, it seems that the JIT
		 * compiler from Sun's JDK decides not to inline those
		 * methods, although it could (they are private final,
		 * hence cannot be overridden) and it would yield better
		 * performance.
		 */
        var A = currentVal[0]
        var B = currentVal[1]
        var C = currentVal[2]
        var D = currentVal[3]
        val X00: Int = (data[0].toInt() and 0xFF
                or (data[0 + 1].toInt() and 0xFF shl 8)
                or (data[0 + 2].toInt() and 0xFF shl 16)
                or (data[0 + 3].toInt() and 0xFF shl 24))
        val X01: Int = (data[4].toInt() and 0xFF
                or (data[4 + 1].toInt() and 0xFF shl 8)
                or (data[4 + 2].toInt() and 0xFF shl 16)
                or (data[4 + 3].toInt() and 0xFF shl 24))
        val X02: Int = (data[8].toInt() and 0xFF
                or (data[8 + 1].toInt() and 0xFF shl 8)
                or (data[8 + 2].toInt() and 0xFF shl 16)
                or (data[8 + 3].toInt() and 0xFF shl 24))
        val X03: Int = (data[12].toInt() and 0xFF
                or (data[12 + 1].toInt() and 0xFF shl 8)
                or (data[12 + 2].toInt() and 0xFF shl 16)
                or (data[12 + 3].toInt() and 0xFF shl 24))
        val X04: Int = (data[16].toInt() and 0xFF
                or (data[16 + 1].toInt() and 0xFF shl 8)
                or (data[16 + 2].toInt() and 0xFF shl 16)
                or (data[16 + 3].toInt() and 0xFF shl 24))
        val X05: Int = (data[20].toInt() and 0xFF
                or (data[20 + 1].toInt() and 0xFF shl 8)
                or (data[20 + 2].toInt() and 0xFF shl 16)
                or (data[20 + 3].toInt() and 0xFF shl 24))
        val X06: Int = (data[24].toInt() and 0xFF
                or (data[24 + 1].toInt() and 0xFF shl 8)
                or (data[24 + 2].toInt() and 0xFF shl 16)
                or (data[24 + 3].toInt() and 0xFF shl 24))
        val X07: Int = (data[28].toInt() and 0xFF
                or (data[28 + 1].toInt() and 0xFF shl 8)
                or (data[28 + 2].toInt() and 0xFF shl 16)
                or (data[28 + 3].toInt() and 0xFF shl 24))
        val X08: Int = (data[32].toInt() and 0xFF
                or (data[32 + 1].toInt() and 0xFF shl 8)
                or (data[32 + 2].toInt() and 0xFF shl 16)
                or (data[32 + 3].toInt() and 0xFF shl 24))
        val X09: Int = (data[36].toInt() and 0xFF
                or (data[36 + 1].toInt() and 0xFF shl 8)
                or (data[36 + 2].toInt() and 0xFF shl 16)
                or (data[36 + 3].toInt() and 0xFF shl 24))
        val X10: Int = (data[40].toInt() and 0xFF
                or (data[40 + 1].toInt() and 0xFF shl 8)
                or (data[40 + 2].toInt() and 0xFF shl 16)
                or (data[40 + 3].toInt() and 0xFF shl 24))
        val X11: Int = (data[44].toInt() and 0xFF
                or (data[44 + 1].toInt() and 0xFF shl 8)
                or (data[44 + 2].toInt() and 0xFF shl 16)
                or (data[44 + 3].toInt() and 0xFF shl 24))
        val X12: Int = (data[48].toInt() and 0xFF
                or (data[48 + 1].toInt() and 0xFF shl 8)
                or (data[48 + 2].toInt() and 0xFF shl 16)
                or (data[48 + 3].toInt() and 0xFF shl 24))
        val X13: Int = (data[52].toInt() and 0xFF
                or (data[52 + 1].toInt() and 0xFF shl 8)
                or (data[52 + 2].toInt() and 0xFF shl 16)
                or (data[52 + 3].toInt() and 0xFF shl 24))
        val X14: Int = (data[56].toInt() and 0xFF
                or (data[56 + 1].toInt() and 0xFF shl 8)
                or (data[56 + 2].toInt() and 0xFF shl 16)
                or (data[56 + 3].toInt() and 0xFF shl 24))
        val X15: Int = (data[60].toInt() and 0xFF
                or (data[60 + 1].toInt() and 0xFF shl 8)
                or (data[60 + 2].toInt() and 0xFF shl 16)
                or (data[60 + 3].toInt() and 0xFF shl 24))
        var T: Int
        T = A + (C xor D and B xor D) + X00
        A = T shl 3 or (T ushr 32 - 3)
        T = D + (B xor C and A xor C) + X01
        D = T shl 7 or (T ushr 32 - 7)
        T = C + (A xor B and D xor B) + X02
        C = T shl 11 or (T ushr 32 - 11)
        T = B + (D xor A and C xor A) + X03
        B = T shl 19 or (T ushr 32 - 19)
        T = A + (C xor D and B xor D) + X04
        A = T shl 3 or (T ushr 32 - 3)
        T = D + (B xor C and A xor C) + X05
        D = T shl 7 or (T ushr 32 - 7)
        T = C + (A xor B and D xor B) + X06
        C = T shl 11 or (T ushr 32 - 11)
        T = B + (D xor A and C xor A) + X07
        B = T shl 19 or (T ushr 32 - 19)
        T = A + (C xor D and B xor D) + X08
        A = T shl 3 or (T ushr 32 - 3)
        T = D + (B xor C and A xor C) + X09
        D = T shl 7 or (T ushr 32 - 7)
        T = C + (A xor B and D xor B) + X10
        C = T shl 11 or (T ushr 32 - 11)
        T = B + (D xor A and C xor A) + X11
        B = T shl 19 or (T ushr 32 - 19)
        T = A + (C xor D and B xor D) + X12
        A = T shl 3 or (T ushr 32 - 3)
        T = D + (B xor C and A xor C) + X13
        D = T shl 7 or (T ushr 32 - 7)
        T = C + (A xor B and D xor B) + X14
        C = T shl 11 or (T ushr 32 - 11)
        T = B + (D xor A and C xor A) + X15
        B = T shl 19 or (T ushr 32 - 19)
        T = A + (D and C or (D or C and B)) + X00 + 0x5A827999
        A = T shl 3 or (T ushr 32 - 3)
        T = D + (C and B or (C or B and A)) + X04 + 0x5A827999
        D = T shl 5 or (T ushr 32 - 5)
        T = C + (B and A or (B or A and D)) + X08 + 0x5A827999
        C = T shl 9 or (T ushr 32 - 9)
        T = B + (A and D or (A or D and C)) + X12 + 0x5A827999
        B = T shl 13 or (T ushr 32 - 13)
        T = A + (D and C or (D or C and B)) + X01 + 0x5A827999
        A = T shl 3 or (T ushr 32 - 3)
        T = D + (C and B or (C or B and A)) + X05 + 0x5A827999
        D = T shl 5 or (T ushr 32 - 5)
        T = C + (B and A or (B or A and D)) + X09 + 0x5A827999
        C = T shl 9 or (T ushr 32 - 9)
        T = B + (A and D or (A or D and C)) + X13 + 0x5A827999
        B = T shl 13 or (T ushr 32 - 13)
        T = A + (D and C or (D or C and B)) + X02 + 0x5A827999
        A = T shl 3 or (T ushr 32 - 3)
        T = D + (C and B or (C or B and A)) + X06 + 0x5A827999
        D = T shl 5 or (T ushr 32 - 5)
        T = C + (B and A or (B or A and D)) + X10 + 0x5A827999
        C = T shl 9 or (T ushr 32 - 9)
        T = B + (A and D or (A or D and C)) + X14 + 0x5A827999
        B = T shl 13 or (T ushr 32 - 13)
        T = A + (D and C or (D or C and B)) + X03 + 0x5A827999
        A = T shl 3 or (T ushr 32 - 3)
        T = D + (C and B or (C or B and A)) + X07 + 0x5A827999
        D = T shl 5 or (T ushr 32 - 5)
        T = C + (B and A or (B or A and D)) + X11 + 0x5A827999
        C = T shl 9 or (T ushr 32 - 9)
        T = B + (A and D or (A or D and C)) + X15 + 0x5A827999
        B = T shl 13 or (T ushr 32 - 13)
        T = A + (B xor C xor D) + X00 + 0x6ED9EBA1
        A = T shl 3 or (T ushr 32 - 3)
        T = D + (A xor B xor C) + X08 + 0x6ED9EBA1
        D = T shl 9 or (T ushr 32 - 9)
        T = C + (D xor A xor B) + X04 + 0x6ED9EBA1
        C = T shl 11 or (T ushr 32 - 11)
        T = B + (C xor D xor A) + X12 + 0x6ED9EBA1
        B = T shl 15 or (T ushr 32 - 15)
        T = A + (B xor C xor D) + X02 + 0x6ED9EBA1
        A = T shl 3 or (T ushr 32 - 3)
        T = D + (A xor B xor C) + X10 + 0x6ED9EBA1
        D = T shl 9 or (T ushr 32 - 9)
        T = C + (D xor A xor B) + X06 + 0x6ED9EBA1
        C = T shl 11 or (T ushr 32 - 11)
        T = B + (C xor D xor A) + X14 + 0x6ED9EBA1
        B = T shl 15 or (T ushr 32 - 15)
        T = A + (B xor C xor D) + X01 + 0x6ED9EBA1
        A = T shl 3 or (T ushr 32 - 3)
        T = D + (A xor B xor C) + X09 + 0x6ED9EBA1
        D = T shl 9 or (T ushr 32 - 9)
        T = C + (D xor A xor B) + X05 + 0x6ED9EBA1
        C = T shl 11 or (T ushr 32 - 11)
        T = B + (C xor D xor A) + X13 + 0x6ED9EBA1
        B = T shl 15 or (T ushr 32 - 15)
        T = A + (B xor C xor D) + X03 + 0x6ED9EBA1
        A = T shl 3 or (T ushr 32 - 3)
        T = D + (A xor B xor C) + X11 + 0x6ED9EBA1
        D = T shl 9 or (T ushr 32 - 9)
        T = C + (D xor A xor B) + X07 + 0x6ED9EBA1
        C = T shl 11 or (T ushr 32 - 11)
        T = B + (C xor D xor A) + X15 + 0x6ED9EBA1
        B = T shl 15 or (T ushr 32 - 15)
        currentVal[0] += A
        currentVal[1] += B
        currentVal[2] += C
        currentVal[3] += D
    }

    override fun toString(): String {
        return "MD4"
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
            buf[off + 3] = (`val` shr 24 and 0xff).toByte()
            buf[off + 2] = (`val` shr 16 and 0xff).toByte()
            buf[off + 1] = (`val` shr 8 and 0xff).toByte()
            buf[off + 0] = (`val` and 0xff).toByte()
        }
    }
}
