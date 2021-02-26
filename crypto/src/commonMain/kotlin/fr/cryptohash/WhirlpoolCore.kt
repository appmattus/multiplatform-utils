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

/**
 *
 * This class implements the core operations for the Whirlpool digest
 * algorithm family. The three variants differ only in the tables of
 * constants which are provided to this implementation in the constructor.
 *
 * @version   $Revision: 214 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
abstract class WhirlpoolCore<D : WhirlpoolCore<D>>(
    private val T0: LongArray,
    private val T1: LongArray,
    private val T2: LongArray,
    private val T3: LongArray,
    private val T4: LongArray,
    private val T5: LongArray,
    private val T6: LongArray,
    private val T7: LongArray,
    private val RC: LongArray
) : MDHelper<D>(false, 32) {

    private var state0: Long = 0
    private var state1: Long = 0
    private var state2: Long = 0
    private var state3: Long = 0
    private var state4: Long = 0
    private var state5: Long = 0
    private var state6: Long = 0
    private var state7: Long = 0

    override fun copyState(dest: D): D {
        dest.state0 = state0
        dest.state1 = state1
        dest.state2 = state2
        dest.state3 = state3
        dest.state4 = state4
        dest.state5 = state5
        dest.state6 = state6
        dest.state7 = state7
        return super.copyState(dest)
    }

    override val digestLength: Int
        get() = 64

    override val blockLength: Int
        get() = 64

    override fun engineReset() {
        state0 = 0
        state1 = 0
        state2 = 0
        state3 = 0
        state4 = 0
        state5 = 0
        state6 = 0
        state7 = 0
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        makeMDPadding()
        encodeLELong(state0, output, outputOffset)
        encodeLELong(state1, output, outputOffset + 8)
        encodeLELong(state2, output, outputOffset + 16)
        encodeLELong(state3, output, outputOffset + 24)
        encodeLELong(state4, output, outputOffset + 32)
        encodeLELong(state5, output, outputOffset + 40)
        encodeLELong(state6, output, outputOffset + 48)
        encodeLELong(state7, output, outputOffset + 56)
    }

    override fun doInit() {
        engineReset()
    }

    @Suppress("JoinDeclarationAndAssignment")
    override fun processBlock(data: ByteArray) {
        var n0 = decodeLELong(data, 0)
        val sn0 = n0
        var n1 = decodeLELong(data, 8)
        val sn1 = n1
        var n2 = decodeLELong(data, 16)
        val sn2 = n2
        var n3 = decodeLELong(data, 24)
        val sn3 = n3
        var n4 = decodeLELong(data, 32)
        val sn4 = n4
        var n5 = decodeLELong(data, 40)
        val sn5 = n5
        var n6 = decodeLELong(data, 48)
        val sn6 = n6
        var n7 = decodeLELong(data, 56)
        val sn7 = n7
        var h0 = state0
        var h1 = state1
        var h2 = state2
        var h3 = state3
        var h4 = state4
        var h5 = state5
        var h6 = state6
        var h7 = state7
        var r: Int
        n0 = n0 xor h0
        n1 = n1 xor h1
        n2 = n2 xor h2
        n3 = n3 xor h3
        n4 = n4 xor h4
        n5 = n5 xor h5
        n6 = n6 xor h6
        n7 = n7 xor h7
        r = 0
        while (r < 10) {
            var t0: Long
            var t1: Long
            var t2: Long
            var t3: Long
            var t4: Long
            var t5: Long
            var t6: Long
            var t7: Long
            t0 = (T0[h0.toInt() and 0xFF]
                    xor T1[h7.toInt() shr 8 and 0xFF]
                    xor T2[h6.toInt() shr 16 and 0xFF]
                    xor T3[h5.toInt() shr 24 and 0xFF]
                    xor T4[(h4 shr 32).toInt() and 0xFF]
                    xor T5[(h3 shr 40).toInt() and 0xFF]
                    xor T6[(h2 shr 48).toInt() and 0xFF]
                    xor T7[(h1 shr 56).toInt() and 0xFF]
                    xor RC[r])
            t1 = (T0[h1.toInt() and 0xFF]
                    xor T1[h0.toInt() shr 8 and 0xFF]
                    xor T2[h7.toInt() shr 16 and 0xFF]
                    xor T3[h6.toInt() shr 24 and 0xFF]
                    xor T4[(h5 shr 32).toInt() and 0xFF]
                    xor T5[(h4 shr 40).toInt() and 0xFF]
                    xor T6[(h3 shr 48).toInt() and 0xFF]
                    xor T7[(h2 shr 56).toInt() and 0xFF])
            t2 = (T0[h2.toInt() and 0xFF]
                    xor T1[h1.toInt() shr 8 and 0xFF]
                    xor T2[h0.toInt() shr 16 and 0xFF]
                    xor T3[h7.toInt() shr 24 and 0xFF]
                    xor T4[(h6 shr 32).toInt() and 0xFF]
                    xor T5[(h5 shr 40).toInt() and 0xFF]
                    xor T6[(h4 shr 48).toInt() and 0xFF]
                    xor T7[(h3 shr 56).toInt() and 0xFF])
            t3 = (T0[h3.toInt() and 0xFF]
                    xor T1[h2.toInt() shr 8 and 0xFF]
                    xor T2[h1.toInt() shr 16 and 0xFF]
                    xor T3[h0.toInt() shr 24 and 0xFF]
                    xor T4[(h7 shr 32).toInt() and 0xFF]
                    xor T5[(h6 shr 40).toInt() and 0xFF]
                    xor T6[(h5 shr 48).toInt() and 0xFF]
                    xor T7[(h4 shr 56).toInt() and 0xFF])
            t4 = (T0[h4.toInt() and 0xFF]
                    xor T1[h3.toInt() shr 8 and 0xFF]
                    xor T2[h2.toInt() shr 16 and 0xFF]
                    xor T3[h1.toInt() shr 24 and 0xFF]
                    xor T4[(h0 shr 32).toInt() and 0xFF]
                    xor T5[(h7 shr 40).toInt() and 0xFF]
                    xor T6[(h6 shr 48).toInt() and 0xFF]
                    xor T7[(h5 shr 56).toInt() and 0xFF])
            t5 = (T0[h5.toInt() and 0xFF]
                    xor T1[h4.toInt() shr 8 and 0xFF]
                    xor T2[h3.toInt() shr 16 and 0xFF]
                    xor T3[h2.toInt() shr 24 and 0xFF]
                    xor T4[(h1 shr 32).toInt() and 0xFF]
                    xor T5[(h0 shr 40).toInt() and 0xFF]
                    xor T6[(h7 shr 48).toInt() and 0xFF]
                    xor T7[(h6 shr 56).toInt() and 0xFF])
            t6 = (T0[h6.toInt() and 0xFF]
                    xor T1[h5.toInt() shr 8 and 0xFF]
                    xor T2[h4.toInt() shr 16 and 0xFF]
                    xor T3[h3.toInt() shr 24 and 0xFF]
                    xor T4[(h2 shr 32).toInt() and 0xFF]
                    xor T5[(h1 shr 40).toInt() and 0xFF]
                    xor T6[(h0 shr 48).toInt() and 0xFF]
                    xor T7[(h7 shr 56).toInt() and 0xFF])
            t7 = (T0[h7.toInt() and 0xFF]
                    xor T1[h6.toInt() shr 8 and 0xFF]
                    xor T2[h5.toInt() shr 16 and 0xFF]
                    xor T3[h4.toInt() shr 24 and 0xFF]
                    xor T4[(h3 shr 32).toInt() and 0xFF]
                    xor T5[(h2 shr 40).toInt() and 0xFF]
                    xor T6[(h1 shr 48).toInt() and 0xFF]
                    xor T7[(h0 shr 56).toInt() and 0xFF])
            h0 = t0
            h1 = t1
            h2 = t2
            h3 = t3
            h4 = t4
            h5 = t5
            h6 = t6
            h7 = t7
            t0 = (T0[n0.toInt() and 0xFF]
                    xor T1[n7.toInt() shr 8 and 0xFF]
                    xor T2[n6.toInt() shr 16 and 0xFF]
                    xor T3[n5.toInt() shr 24 and 0xFF]
                    xor T4[(n4 shr 32).toInt() and 0xFF]
                    xor T5[(n3 shr 40).toInt() and 0xFF]
                    xor T6[(n2 shr 48).toInt() and 0xFF]
                    xor T7[(n1 shr 56).toInt() and 0xFF]
                    xor h0)
            t1 = (T0[n1.toInt() and 0xFF]
                    xor T1[n0.toInt() shr 8 and 0xFF]
                    xor T2[n7.toInt() shr 16 and 0xFF]
                    xor T3[n6.toInt() shr 24 and 0xFF]
                    xor T4[(n5 shr 32).toInt() and 0xFF]
                    xor T5[(n4 shr 40).toInt() and 0xFF]
                    xor T6[(n3 shr 48).toInt() and 0xFF]
                    xor T7[(n2 shr 56).toInt() and 0xFF]
                    xor h1)
            t2 = (T0[n2.toInt() and 0xFF]
                    xor T1[n1.toInt() shr 8 and 0xFF]
                    xor T2[n0.toInt() shr 16 and 0xFF]
                    xor T3[n7.toInt() shr 24 and 0xFF]
                    xor T4[(n6 shr 32).toInt() and 0xFF]
                    xor T5[(n5 shr 40).toInt() and 0xFF]
                    xor T6[(n4 shr 48).toInt() and 0xFF]
                    xor T7[(n3 shr 56).toInt() and 0xFF]
                    xor h2)
            t3 = (T0[n3.toInt() and 0xFF]
                    xor T1[n2.toInt() shr 8 and 0xFF]
                    xor T2[n1.toInt() shr 16 and 0xFF]
                    xor T3[n0.toInt() shr 24 and 0xFF]
                    xor T4[(n7 shr 32).toInt() and 0xFF]
                    xor T5[(n6 shr 40).toInt() and 0xFF]
                    xor T6[(n5 shr 48).toInt() and 0xFF]
                    xor T7[(n4 shr 56).toInt() and 0xFF]
                    xor h3)
            t4 = (T0[n4.toInt() and 0xFF]
                    xor T1[n3.toInt() shr 8 and 0xFF]
                    xor T2[n2.toInt() shr 16 and 0xFF]
                    xor T3[n1.toInt() shr 24 and 0xFF]
                    xor T4[(n0 shr 32).toInt() and 0xFF]
                    xor T5[(n7 shr 40).toInt() and 0xFF]
                    xor T6[(n6 shr 48).toInt() and 0xFF]
                    xor T7[(n5 shr 56).toInt() and 0xFF]
                    xor h4)
            t5 = (T0[n5.toInt() and 0xFF]
                    xor T1[n4.toInt() shr 8 and 0xFF]
                    xor T2[n3.toInt() shr 16 and 0xFF]
                    xor T3[n2.toInt() shr 24 and 0xFF]
                    xor T4[(n1 shr 32).toInt() and 0xFF]
                    xor T5[(n0 shr 40).toInt() and 0xFF]
                    xor T6[(n7 shr 48).toInt() and 0xFF]
                    xor T7[(n6 shr 56).toInt() and 0xFF]
                    xor h5)
            t6 = (T0[n6.toInt() and 0xFF]
                    xor T1[n5.toInt() shr 8 and 0xFF]
                    xor T2[n4.toInt() shr 16 and 0xFF]
                    xor T3[n3.toInt() shr 24 and 0xFF]
                    xor T4[(n2 shr 32).toInt() and 0xFF]
                    xor T5[(n1 shr 40).toInt() and 0xFF]
                    xor T6[(n0 shr 48).toInt() and 0xFF]
                    xor T7[(n7 shr 56).toInt() and 0xFF]
                    xor h6)
            t7 = (T0[n7.toInt() and 0xFF]
                    xor T1[n6.toInt() shr 8 and 0xFF]
                    xor T2[n5.toInt() shr 16 and 0xFF]
                    xor T3[n4.toInt() shr 24 and 0xFF]
                    xor T4[(n3 shr 32).toInt() and 0xFF]
                    xor T5[(n2 shr 40).toInt() and 0xFF]
                    xor T6[(n1 shr 48).toInt() and 0xFF]
                    xor T7[(n0 shr 56).toInt() and 0xFF]
                    xor h7)
            n0 = t0
            n1 = t1
            n2 = t2
            n3 = t3
            n4 = t4
            n5 = t5
            n6 = t6
            n7 = t7
            r++
        }
        state0 = state0 xor (n0 xor sn0)
        state1 = state1 xor (n1 xor sn1)
        state2 = state2 xor (n2 xor sn2)
        state3 = state3 xor (n3 xor sn3)
        state4 = state4 xor (n4 xor sn4)
        state5 = state5 xor (n5 xor sn5)
        state6 = state6 xor (n6 xor sn6)
        state7 = state7 xor (n7 xor sn7)
    }

    companion object {
        /**
         * Decode a 64-bit little-endian integer.
         *
         * @param buf   the source buffer
         * @param off   the source offset
         * @return  the decoded integer
         */
        private fun decodeLELong(buf: ByteArray, off: Int): Long {
            return (buf[off + 0].toLong() and 0xFF
                    or ((buf[off + 1].toLong() and 0xFF) shl 8)
                    or ((buf[off + 2].toLong() and 0xFF) shl 16)
                    or ((buf[off + 3].toLong() and 0xFF) shl 24)
                    or ((buf[off + 4].toLong() and 0xFF) shl 32)
                    or ((buf[off + 5].toLong() and 0xFF) shl 40)
                    or ((buf[off + 6].toLong() and 0xFF) shl 48)
                    or ((buf[off + 7].toLong() and 0xFF) shl 56))
        }

        /**
         * Encode a 64-bit integer with little-endian convention.
         *
         * @param val   the integer to encode
         * @param dst   the destination buffer
         * @param off   the destination offset
         */
        private fun encodeLELong(`val`: Long, dst: ByteArray, off: Int) {
            dst[off + 0] = `val`.toByte()
            dst[off + 1] = (`val`.toInt() ushr 8).toByte()
            dst[off + 2] = (`val`.toInt() ushr 16).toByte()
            dst[off + 3] = (`val`.toInt() ushr 24).toByte()
            dst[off + 4] = (`val` ushr 32).toByte()
            dst[off + 5] = (`val` ushr 40).toByte()
            dst[off + 6] = (`val` ushr 48).toByte()
            dst[off + 7] = (`val` ushr 56).toByte()
        }
    }
}
