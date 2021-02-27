/*
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
 */

package fr.cryptohash

import com.appmattus.crypto.Algorithm

/**
 *
 * This class implements the MD5 digest algorithm under the
 * [Digest] API, using the [DigestEngine] class.
 * MD5 is defined in RFC 1321.
 *
 * @version   $Revision: 214 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
internal class MD5 : MDHelper<MD5>(true, 8) {

    private lateinit var currentVal: IntArray
    private lateinit var x: IntArray

    override fun copy(): MD5 {
        val d = MD5()
        currentVal.copyInto(d.currentVal, 0, 0, currentVal.size)
        return copyState(d)
    }

    override val digestLength: Int
        get() = 16

    override val blockLength: Int
        get() = Algorithm.MD5.blockLength

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
        x = IntArray(16)
        engineReset()
    }

    override fun processBlock(data: ByteArray) {
        var a = currentVal[0]
        var b = currentVal[1]
        var c = currentVal[2]
        var d = currentVal[3]
        for (i in 0..15) x[i] = decodeLEInt(data, 4 * i)
        a = b + circularLeft(a + f(b, c, d) + x[0] + -0x28955b88, 7)
        d = a + circularLeft(d + f(a, b, c) + x[1] + -0x173848aa, 12)
        c = d + circularLeft(c + f(d, a, b) + x[2] + 0x242070DB, 17)
        b = c + circularLeft(b + f(c, d, a) + x[3] + -0x3e423112, 22)
        a = b + circularLeft(a + f(b, c, d) + x[4] + -0xa83f051, 7)
        d = a + circularLeft(d + f(a, b, c) + x[5] + 0x4787C62A, 12)
        c = d + circularLeft(c + f(d, a, b) + x[6] + -0x57cfb9ed, 17)
        b = c + circularLeft(b + f(c, d, a) + x[7] + -0x2b96aff, 22)
        a = b + circularLeft(a + f(b, c, d) + x[8] + 0x698098D8, 7)
        d = a + circularLeft(d + f(a, b, c) + x[9] + -0x74bb0851, 12)
        c = d + circularLeft(c + f(d, a, b) + x[10] + -0xa44f, 17)
        b = c + circularLeft(b + f(c, d, a) + x[11] + -0x76a32842, 22)
        a = b + circularLeft(a + f(b, c, d) + x[12] + 0x6B901122, 7)
        d = a + circularLeft(d + f(a, b, c) + x[13] + -0x2678e6d, 12)
        c = d + circularLeft(c + f(d, a, b) + x[14] + -0x5986bc72, 17)
        b = c + circularLeft(b + f(c, d, a) + x[15] + 0x49B40821, 22)
        a = b + circularLeft(a + g(b, c, d) + x[1] + -0x9e1da9e, 5)
        d = a + circularLeft(d + g(a, b, c) + x[6] + -0x3fbf4cc0, 9)
        c = d + circularLeft(c + g(d, a, b) + x[11] + 0x265E5A51, 14)
        b = c + circularLeft(b + g(c, d, a) + x[0] + -0x16493856, 20)
        a = b + circularLeft(a + g(b, c, d) + x[5] + -0x29d0efa3, 5)
        d = a + circularLeft(d + g(a, b, c) + x[10] + 0x02441453, 9)
        c = d + circularLeft(c + g(d, a, b) + x[15] + -0x275e197f, 14)
        b = c + circularLeft(b + g(c, d, a) + x[4] + -0x182c0438, 20)
        a = b + circularLeft(a + g(b, c, d) + x[9] + 0x21E1CDE6, 5)
        d = a + circularLeft(d + g(a, b, c) + x[14] + -0x3cc8f82a, 9)
        c = d + circularLeft(c + g(d, a, b) + x[3] + -0xb2af279, 14)
        b = c + circularLeft(b + g(c, d, a) + x[8] + 0x455A14ED, 20)
        a = b + circularLeft(a + g(b, c, d) + x[13] + -0x561c16fb, 5)
        d = a + circularLeft(d + g(a, b, c) + x[2] + -0x3105c08, 9)
        c = d + circularLeft(c + g(d, a, b) + x[7] + 0x676F02D9, 14)
        b = c + circularLeft(b + g(c, d, a) + x[12] + -0x72d5b376, 20)
        a = b + circularLeft(a + h(b, c, d) + x[5] + -0x5c6be, 4)
        d = a + circularLeft(d + h(a, b, c) + x[8] + -0x788e097f, 11)
        c = d + circularLeft(c + h(d, a, b) + x[11] + 0x6D9D6122, 16)
        b = c + circularLeft(b + h(c, d, a) + x[14] + -0x21ac7f4, 23)
        a = b + circularLeft(a + h(b, c, d) + x[1] + -0x5b4115bc, 4)
        d = a + circularLeft(d + h(a, b, c) + x[4] + 0x4BDECFA9, 11)
        c = d + circularLeft(c + h(d, a, b) + x[7] + -0x944b4a0, 16)
        b = c + circularLeft(b + h(c, d, a) + x[10] + -0x41404390, 23)
        a = b + circularLeft(a + h(b, c, d) + x[13] + 0x289B7EC6, 4)
        d = a + circularLeft(d + h(a, b, c) + x[0] + -0x155ed806, 11)
        c = d + circularLeft(c + h(d, a, b) + x[3] + -0x2b10cf7b, 16)
        b = c + circularLeft(b + h(c, d, a) + x[6] + 0x04881D05, 23)
        a = b + circularLeft(a + h(b, c, d) + x[9] + -0x262b2fc7, 4)
        d = a + circularLeft(d + h(a, b, c) + x[12] + -0x1924661b, 11)
        c = d + circularLeft(c + h(d, a, b) + x[15] + 0x1FA27CF8, 16)
        b = c + circularLeft(b + h(c, d, a) + x[2] + -0x3b53a99b, 23)
        a = b + circularLeft(a + i(b, c, d) + x[0] + -0xbd6ddbc, 6)
        d = a + circularLeft(d + i(a, b, c) + x[7] + 0x432AFF97, 10)
        c = d + circularLeft(c + i(d, a, b) + x[14] + -0x546bdc59, 15)
        b = c + circularLeft(b + i(c, d, a) + x[5] + -0x36c5fc7, 21)
        a = b + circularLeft(a + i(b, c, d) + x[12] + 0x655B59C3, 6)
        d = a + circularLeft(d + i(a, b, c) + x[3] + -0x70f3336e, 10)
        c = d + circularLeft(c + i(d, a, b) + x[10] + -0x100b83, 15)
        b = c + circularLeft(b + i(c, d, a) + x[1] + -0x7a7ba22f, 21)
        a = b + circularLeft(a + i(b, c, d) + x[8] + 0x6FA87E4F, 6)
        d = a + circularLeft(d + i(a, b, c) + x[15] + -0x1d31920, 10)
        c = d + circularLeft(c + i(d, a, b) + x[6] + -0x5cfebcec, 15)
        b = c + circularLeft(b + i(c, d, a) + x[13] + 0x4E0811A1, 21)
        a = b + circularLeft(a + i(b, c, d) + x[4] + -0x8ac817e, 6)
        d = a + circularLeft(d + i(a, b, c) + x[11] + -0x42c50dcb, 10)
        c = d + circularLeft(c + i(d, a, b) + x[2] + 0x2AD7D2BB, 15)
        b = c + circularLeft(b + i(c, d, a) + x[9] + -0x14792c6f, 21)
        currentVal[0] += a
        currentVal[1] += b
        currentVal[2] += c
        currentVal[3] += d
    }

    override fun toString(): String {
        return "MD5"
    }

    companion object {
        /**
         * Perform a circular rotation by `n` to the left
         * of the 32-bit word `x`. The `n`
         * parameter must be between 1 and 31 (inclusive).
         *
         * @param x   the value to rotate
         * @param n   the rotation count (between 1 and 31)
         * @return  the rotated value
         */
        private fun circularLeft(x: Int, n: Int): Int {
            return x shl n or (x ushr 32 - n)
        }

        /**
         * Encode the 32-bit word `val` into the array
         * `buf` at offset `off`, in little-endian
         * convention (least significant byte first).
         *
         * @param val   the value to encode
         * @param buf   the destination buffer
         * @param off   the destination offset
         */
        private fun encodeLEInt(`val`: Int, buf: ByteArray?, off: Int) {
            buf!![off + 0] = `val`.toByte()
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
        private fun decodeLEInt(buf: ByteArray?, off: Int): Int {
            return (buf!![off].toInt() and 0xFF
                    or (buf[off + 1].toInt() and 0xFF shl 8)
                    or (buf[off + 2].toInt() and 0xFF shl 16)
                    or (buf[off + 3].toInt() and 0xFF shl 24))
        }

        private fun f(x: Int, y: Int, z: Int): Int {
            return y and x or (z and x.inv())
        }

        private fun g(x: Int, y: Int, z: Int): Int {
            return x and z or (y and z.inv())
        }

        private fun h(x: Int, y: Int, z: Int): Int {
            return x xor y xor z
        }

        private fun i(x: Int, y: Int, z: Int): Int {
            return y xor (x or z.inv())
        }
    }
}
