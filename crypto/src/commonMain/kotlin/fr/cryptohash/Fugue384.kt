// $Id: Fugue384.java 159 2010-05-01 15:41:17Z tp $
package fr.cryptohash

/**
 * This class implements the Fugue-384 hash function under the
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
 * @version   $Revision: 159 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Fugue384
/**
 * Create the engine.
 */
    : FugueCore() {
    /** @see Digest
     */
    override val digestLength: Int
        get() = 48

    /** @see FugueCore
     */
    override fun dup(): FugueCore {
        return Fugue384()
    }

    /** @see FugueCore
     */
    override fun process(w: Int, buf: ByteArray?, off: Int, num: Int) {
        var w = w
        var off = off
        var num = num
        val S = S
        when (rshift) {
            1 -> {
                S[7] = S[7] xor S[27]
                S[27] = w
                S[35] = S[35] xor S[27]
                S[28] = S[28] xor S[18]
                S[31] = S[31] xor S[21]
                S[24] = S[24] xor S[28]
                S[25] = S[25] xor S[29]
                S[26] = S[26] xor S[30]
                S[6] = S[6] xor S[28]
                S[7] = S[7] xor S[29]
                S[8] = S[8] xor S[30]
                smix(24, 25, 26, 27)
                S[21] = S[21] xor S[25]
                S[22] = S[22] xor S[26]
                S[23] = S[23] xor S[27]
                S[3] = S[3] xor S[25]
                S[4] = S[4] xor S[26]
                S[5] = S[5] xor S[27]
                smix(21, 22, 23, 24)
                S[18] = S[18] xor S[22]
                S[19] = S[19] xor S[23]
                S[20] = S[20] xor S[24]
                S[0] = S[0] xor S[22]
                S[1] = S[1] xor S[23]
                S[2] = S[2] xor S[24]
                smix(18, 19, 20, 21)
                if (num-- <= 0) {
                    rshift = 2
                    return
                }
                w = (buf!![off].toInt() shl 24
                        or (buf[off + 1].toInt() and 0xFF shl 16)
                        or (buf[off + 2].toInt() and 0xFF shl 8)
                        or (buf[off + 3].toInt() and 0xFF))
                off += 4
                S[34] = S[34] xor S[18]
                S[18] = w
                S[26] = S[26] xor S[18]
                S[19] = S[19] xor S[9]
                S[22] = S[22] xor S[12]
                S[15] = S[15] xor S[19]
                S[16] = S[16] xor S[20]
                S[17] = S[17] xor S[21]
                S[33] = S[33] xor S[19]
                S[34] = S[34] xor S[20]
                S[35] = S[35] xor S[21]
                smix(15, 16, 17, 18)
                S[12] = S[12] xor S[16]
                S[13] = S[13] xor S[17]
                S[14] = S[14] xor S[18]
                S[30] = S[30] xor S[16]
                S[31] = S[31] xor S[17]
                S[32] = S[32] xor S[18]
                smix(12, 13, 14, 15)
                S[9] = S[9] xor S[13]
                S[10] = S[10] xor S[14]
                S[11] = S[11] xor S[15]
                S[27] = S[27] xor S[13]
                S[28] = S[28] xor S[14]
                S[29] = S[29] xor S[15]
                smix(9, 10, 11, 12)
                if (num-- <= 0) {
                    rshift = 3
                    return
                }
                w = (buf[off].toInt() shl 24
                        or (buf[off + 1].toInt() and 0xFF shl 16)
                        or (buf[off + 2].toInt() and 0xFF shl 8)
                        or (buf[off + 3].toInt() and 0xFF))
                off += 4
                S[25] = S[25] xor S[9]
                S[9] = w
                S[17] = S[17] xor S[9]
                S[10] = S[10] xor S[0]
                S[13] = S[13] xor S[3]
                S[6] = S[6] xor S[10]
                S[7] = S[7] xor S[11]
                S[8] = S[8] xor S[12]
                S[24] = S[24] xor S[10]
                S[25] = S[25] xor S[11]
                S[26] = S[26] xor S[12]
                smix(6, 7, 8, 9)
                S[3] = S[3] xor S[7]
                S[4] = S[4] xor S[8]
                S[5] = S[5] xor S[9]
                S[21] = S[21] xor S[7]
                S[22] = S[22] xor S[8]
                S[23] = S[23] xor S[9]
                smix(3, 4, 5, 6)
                S[0] = S[0] xor S[4]
                S[1] = S[1] xor S[5]
                S[2] = S[2] xor S[6]
                S[18] = S[18] xor S[4]
                S[19] = S[19] xor S[5]
                S[20] = S[20] xor S[6]
                smix(0, 1, 2, 3)
                if (num-- <= 0) {
                    rshift = 0
                    return
                }
                w = (buf[off].toInt() shl 24
                        or (buf[off + 1].toInt() and 0xFF shl 16)
                        or (buf[off + 2].toInt() and 0xFF shl 8)
                        or (buf[off + 3].toInt() and 0xFF))
                off += 4
            }
            2 -> {
                S[34] = S[34] xor S[18]
                S[18] = w
                S[26] = S[26] xor S[18]
                S[19] = S[19] xor S[9]
                S[22] = S[22] xor S[12]
                S[15] = S[15] xor S[19]
                S[16] = S[16] xor S[20]
                S[17] = S[17] xor S[21]
                S[33] = S[33] xor S[19]
                S[34] = S[34] xor S[20]
                S[35] = S[35] xor S[21]
                smix(15, 16, 17, 18)
                S[12] = S[12] xor S[16]
                S[13] = S[13] xor S[17]
                S[14] = S[14] xor S[18]
                S[30] = S[30] xor S[16]
                S[31] = S[31] xor S[17]
                S[32] = S[32] xor S[18]
                smix(12, 13, 14, 15)
                S[9] = S[9] xor S[13]
                S[10] = S[10] xor S[14]
                S[11] = S[11] xor S[15]
                S[27] = S[27] xor S[13]
                S[28] = S[28] xor S[14]
                S[29] = S[29] xor S[15]
                smix(9, 10, 11, 12)
                if (num-- <= 0) {
                    rshift = 3
                    return
                }
                w = (buf!![off].toInt() shl 24
                        or (buf[off + 1].toInt() and 0xFF shl 16)
                        or (buf[off + 2].toInt() and 0xFF shl 8)
                        or (buf[off + 3].toInt() and 0xFF))
                off += 4
                S[25] = S[25] xor S[9]
                S[9] = w
                S[17] = S[17] xor S[9]
                S[10] = S[10] xor S[0]
                S[13] = S[13] xor S[3]
                S[6] = S[6] xor S[10]
                S[7] = S[7] xor S[11]
                S[8] = S[8] xor S[12]
                S[24] = S[24] xor S[10]
                S[25] = S[25] xor S[11]
                S[26] = S[26] xor S[12]
                smix(6, 7, 8, 9)
                S[3] = S[3] xor S[7]
                S[4] = S[4] xor S[8]
                S[5] = S[5] xor S[9]
                S[21] = S[21] xor S[7]
                S[22] = S[22] xor S[8]
                S[23] = S[23] xor S[9]
                smix(3, 4, 5, 6)
                S[0] = S[0] xor S[4]
                S[1] = S[1] xor S[5]
                S[2] = S[2] xor S[6]
                S[18] = S[18] xor S[4]
                S[19] = S[19] xor S[5]
                S[20] = S[20] xor S[6]
                smix(0, 1, 2, 3)
                if (num-- <= 0) {
                    rshift = 0
                    return
                }
                w = (buf[off].toInt() shl 24
                        or (buf[off + 1].toInt() and 0xFF shl 16)
                        or (buf[off + 2].toInt() and 0xFF shl 8)
                        or (buf[off + 3].toInt() and 0xFF))
                off += 4
            }
            3 -> {
                S[25] = S[25] xor S[9]
                S[9] = w
                S[17] = S[17] xor S[9]
                S[10] = S[10] xor S[0]
                S[13] = S[13] xor S[3]
                S[6] = S[6] xor S[10]
                S[7] = S[7] xor S[11]
                S[8] = S[8] xor S[12]
                S[24] = S[24] xor S[10]
                S[25] = S[25] xor S[11]
                S[26] = S[26] xor S[12]
                smix(6, 7, 8, 9)
                S[3] = S[3] xor S[7]
                S[4] = S[4] xor S[8]
                S[5] = S[5] xor S[9]
                S[21] = S[21] xor S[7]
                S[22] = S[22] xor S[8]
                S[23] = S[23] xor S[9]
                smix(3, 4, 5, 6)
                S[0] = S[0] xor S[4]
                S[1] = S[1] xor S[5]
                S[2] = S[2] xor S[6]
                S[18] = S[18] xor S[4]
                S[19] = S[19] xor S[5]
                S[20] = S[20] xor S[6]
                smix(0, 1, 2, 3)
                if (num-- <= 0) {
                    rshift = 0
                    return
                }
                w = (buf!![off].toInt() shl 24
                        or (buf[off + 1].toInt() and 0xFF shl 16)
                        or (buf[off + 2].toInt() and 0xFF shl 8)
                        or (buf[off + 3].toInt() and 0xFF))
                off += 4
            }
        }
        while (true) {

            /* ================ */S[16] = S[16] xor S[0]
            S[0] = w
            S[8] = S[8] xor S[0]
            S[1] = S[1] xor S[27]
            S[4] = S[4] xor S[30]
            S[33] = S[33] xor S[1]
            S[34] = S[34] xor S[2]
            S[35] = S[35] xor S[3]
            S[15] = S[15] xor S[1]
            S[16] = S[16] xor S[2]
            S[17] = S[17] xor S[3]
            smix(33, 34, 35, 0)
            S[30] = S[30] xor S[34]
            S[31] = S[31] xor S[35]
            S[32] = S[32] xor S[0]
            S[12] = S[12] xor S[34]
            S[13] = S[13] xor S[35]
            S[14] = S[14] xor S[0]
            smix(30, 31, 32, 33)
            S[27] = S[27] xor S[31]
            S[28] = S[28] xor S[32]
            S[29] = S[29] xor S[33]
            S[9] = S[9] xor S[31]
            S[10] = S[10] xor S[32]
            S[11] = S[11] xor S[33]
            smix(27, 28, 29, 30)
            if (num-- <= 0) {
                rshift = 1
                return
            }
            w = (buf!![off].toInt() shl 24
                    or (buf[off + 1].toInt() and 0xFF shl 16)
                    or (buf[off + 2].toInt() and 0xFF shl 8)
                    or (buf[off + 3].toInt() and 0xFF))
            off += 4
            /* ================ */S[7] = S[7] xor S[27]
            S[27] = w
            S[35] = S[35] xor S[27]
            S[28] = S[28] xor S[18]
            S[31] = S[31] xor S[21]
            S[24] = S[24] xor S[28]
            S[25] = S[25] xor S[29]
            S[26] = S[26] xor S[30]
            S[6] = S[6] xor S[28]
            S[7] = S[7] xor S[29]
            S[8] = S[8] xor S[30]
            smix(24, 25, 26, 27)
            S[21] = S[21] xor S[25]
            S[22] = S[22] xor S[26]
            S[23] = S[23] xor S[27]
            S[3] = S[3] xor S[25]
            S[4] = S[4] xor S[26]
            S[5] = S[5] xor S[27]
            smix(21, 22, 23, 24)
            S[18] = S[18] xor S[22]
            S[19] = S[19] xor S[23]
            S[20] = S[20] xor S[24]
            S[0] = S[0] xor S[22]
            S[1] = S[1] xor S[23]
            S[2] = S[2] xor S[24]
            smix(18, 19, 20, 21)
            if (num-- <= 0) {
                rshift = 2
                return
            }
            w = (buf[off].toInt() shl 24
                    or (buf[off + 1].toInt() and 0xFF shl 16)
                    or (buf[off + 2].toInt() and 0xFF shl 8)
                    or (buf[off + 3].toInt() and 0xFF))
            off += 4
            /* ================ */S[34] = S[34] xor S[18]
            S[18] = w
            S[26] = S[26] xor S[18]
            S[19] = S[19] xor S[9]
            S[22] = S[22] xor S[12]
            S[15] = S[15] xor S[19]
            S[16] = S[16] xor S[20]
            S[17] = S[17] xor S[21]
            S[33] = S[33] xor S[19]
            S[34] = S[34] xor S[20]
            S[35] = S[35] xor S[21]
            smix(15, 16, 17, 18)
            S[12] = S[12] xor S[16]
            S[13] = S[13] xor S[17]
            S[14] = S[14] xor S[18]
            S[30] = S[30] xor S[16]
            S[31] = S[31] xor S[17]
            S[32] = S[32] xor S[18]
            smix(12, 13, 14, 15)
            S[9] = S[9] xor S[13]
            S[10] = S[10] xor S[14]
            S[11] = S[11] xor S[15]
            S[27] = S[27] xor S[13]
            S[28] = S[28] xor S[14]
            S[29] = S[29] xor S[15]
            smix(9, 10, 11, 12)
            if (num-- <= 0) {
                rshift = 3
                return
            }
            w = (buf[off].toInt() shl 24
                    or (buf[off + 1].toInt() and 0xFF shl 16)
                    or (buf[off + 2].toInt() and 0xFF shl 8)
                    or (buf[off + 3].toInt() and 0xFF))
            off += 4
            /* ================ */S[25] = S[25] xor S[9]
            S[9] = w
            S[17] = S[17] xor S[9]
            S[10] = S[10] xor S[0]
            S[13] = S[13] xor S[3]
            S[6] = S[6] xor S[10]
            S[7] = S[7] xor S[11]
            S[8] = S[8] xor S[12]
            S[24] = S[24] xor S[10]
            S[25] = S[25] xor S[11]
            S[26] = S[26] xor S[12]
            smix(6, 7, 8, 9)
            S[3] = S[3] xor S[7]
            S[4] = S[4] xor S[8]
            S[5] = S[5] xor S[9]
            S[21] = S[21] xor S[7]
            S[22] = S[22] xor S[8]
            S[23] = S[23] xor S[9]
            smix(3, 4, 5, 6)
            S[0] = S[0] xor S[4]
            S[1] = S[1] xor S[5]
            S[2] = S[2] xor S[6]
            S[18] = S[18] xor S[4]
            S[19] = S[19] xor S[5]
            S[20] = S[20] xor S[6]
            smix(0, 1, 2, 3)
            if (num-- <= 0) {
                rshift = 0
                return
            }
            w = (buf[off].toInt() shl 24
                    or (buf[off + 1].toInt() and 0xFF shl 16)
                    or (buf[off + 2].toInt() and 0xFF shl 8)
                    or (buf[off + 3].toInt() and 0xFF))
            off += 4
        }
    }

    /** @see FugueCore
     */
    override fun processFinal(out: ByteArray?) {
        val S = S
        ror(9 * rshift, 36)
        for (i in 0..17) {
            ror(3, 36)
            cmix36()
            smix(0, 1, 2, 3)
        }
        for (i in 0..12) {
            S[4] = S[4] xor S[0]
            S[12] = S[12] xor S[0]
            S[24] = S[24] xor S[0]
            ror(12, 36)
            smix(0, 1, 2, 3)
            S[4] = S[4] xor S[0]
            S[13] = S[13] xor S[0]
            S[24] = S[24] xor S[0]
            ror(12, 36)
            smix(0, 1, 2, 3)
            S[4] = S[4] xor S[0]
            S[13] = S[13] xor S[0]
            S[25] = S[25] xor S[0]
            ror(11, 36)
            smix(0, 1, 2, 3)
        }
        S[4] = S[4] xor S[0]
        S[12] = S[12] xor S[0]
        S[24] = S[24] xor S[0]
        encodeBEInt(S[1], out!!, 0)
        encodeBEInt(S[2], out, 4)
        encodeBEInt(S[3], out, 8)
        encodeBEInt(S[4], out, 12)
        encodeBEInt(S[12], out, 16)
        encodeBEInt(S[13], out, 20)
        encodeBEInt(S[14], out, 24)
        encodeBEInt(S[15], out, 28)
        encodeBEInt(S[24], out, 32)
        encodeBEInt(S[25], out, 36)
        encodeBEInt(S[26], out, 40)
        encodeBEInt(S[27], out, 44)
    }

    override val iV: IntArray
        get() = Companion.iV

    companion object {
        /** @see FugueCore
         */
        val iV = intArrayOf(
            -0x559e13f3, 0x31252e1f, -0x5fe24b39, 0x00600985,
            0x215ef44a, 0x741b5e9c, -0x596c166, 0x473eb040,
            -0x1afd5176, -0x5663da20, -0x436aae84, 0x5c1095a1
        )
    }
}
