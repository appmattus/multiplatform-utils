// $Id: CubeHashCore.java 232 2010-06-17 14:19:24Z tp $
package fr.cryptohash

/**
 * This class implements the core operations for the CubeHash digest
 * algorithm.
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
 * @version   $Revision: 232 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
abstract class CubeHashCore : DigestEngine() {
    private var x0 = 0
    private var x1 = 0
    private var x2 = 0
    private var x3 = 0
    private var x4 = 0
    private var x5 = 0
    private var x6 = 0
    private var x7 = 0
    private var x8 = 0
    private var x9 = 0
    private var xa = 0
    private var xb = 0
    private var xc = 0
    private var xd = 0
    private var xe = 0
    private var xf = 0
    private var xg = 0
    private var xh = 0
    private var xi = 0
    private var xj = 0
    private var xk = 0
    private var xl = 0
    private var xm = 0
    private var xn = 0
    private var xo = 0
    private var xp = 0
    private var xq = 0
    private var xr = 0
    private var xs = 0
    private var xt = 0
    private var xu = 0
    private var xv = 0
    private fun inputBlock(data: ByteArray) {
        x0 = x0 xor decodeLEInt(data, 0)
        x1 = x1 xor decodeLEInt(data, 4)
        x2 = x2 xor decodeLEInt(data, 8)
        x3 = x3 xor decodeLEInt(data, 12)
        x4 = x4 xor decodeLEInt(data, 16)
        x5 = x5 xor decodeLEInt(data, 20)
        x6 = x6 xor decodeLEInt(data, 24)
        x7 = x7 xor decodeLEInt(data, 28)
    }

    private fun sixteenRounds() {
        for (i in 0..7) {
            xg = x0 + xg
            x0 = x0 shl 7 or (x0 ushr 32 - 7)
            xh = x1 + xh
            x1 = x1 shl 7 or (x1 ushr 32 - 7)
            xi = x2 + xi
            x2 = x2 shl 7 or (x2 ushr 32 - 7)
            xj = x3 + xj
            x3 = x3 shl 7 or (x3 ushr 32 - 7)
            xk = x4 + xk
            x4 = x4 shl 7 or (x4 ushr 32 - 7)
            xl = x5 + xl
            x5 = x5 shl 7 or (x5 ushr 32 - 7)
            xm = x6 + xm
            x6 = x6 shl 7 or (x6 ushr 32 - 7)
            xn = x7 + xn
            x7 = x7 shl 7 or (x7 ushr 32 - 7)
            xo = x8 + xo
            x8 = x8 shl 7 or (x8 ushr 32 - 7)
            xp = x9 + xp
            x9 = x9 shl 7 or (x9 ushr 32 - 7)
            xq = xa + xq
            xa = xa shl 7 or (xa ushr 32 - 7)
            xr = xb + xr
            xb = xb shl 7 or (xb ushr 32 - 7)
            xs = xc + xs
            xc = xc shl 7 or (xc ushr 32 - 7)
            xt = xd + xt
            xd = xd shl 7 or (xd ushr 32 - 7)
            xu = xe + xu
            xe = xe shl 7 or (xe ushr 32 - 7)
            xv = xf + xv
            xf = xf shl 7 or (xf ushr 32 - 7)
            x8 = x8 xor xg
            x9 = x9 xor xh
            xa = xa xor xi
            xb = xb xor xj
            xc = xc xor xk
            xd = xd xor xl
            xe = xe xor xm
            xf = xf xor xn
            x0 = x0 xor xo
            x1 = x1 xor xp
            x2 = x2 xor xq
            x3 = x3 xor xr
            x4 = x4 xor xs
            x5 = x5 xor xt
            x6 = x6 xor xu
            x7 = x7 xor xv
            xi = x8 + xi
            x8 = x8 shl 11 or (x8 ushr 32 - 11)
            xj = x9 + xj
            x9 = x9 shl 11 or (x9 ushr 32 - 11)
            xg = xa + xg
            xa = xa shl 11 or (xa ushr 32 - 11)
            xh = xb + xh
            xb = xb shl 11 or (xb ushr 32 - 11)
            xm = xc + xm
            xc = xc shl 11 or (xc ushr 32 - 11)
            xn = xd + xn
            xd = xd shl 11 or (xd ushr 32 - 11)
            xk = xe + xk
            xe = xe shl 11 or (xe ushr 32 - 11)
            xl = xf + xl
            xf = xf shl 11 or (xf ushr 32 - 11)
            xq = x0 + xq
            x0 = x0 shl 11 or (x0 ushr 32 - 11)
            xr = x1 + xr
            x1 = x1 shl 11 or (x1 ushr 32 - 11)
            xo = x2 + xo
            x2 = x2 shl 11 or (x2 ushr 32 - 11)
            xp = x3 + xp
            x3 = x3 shl 11 or (x3 ushr 32 - 11)
            xu = x4 + xu
            x4 = x4 shl 11 or (x4 ushr 32 - 11)
            xv = x5 + xv
            x5 = x5 shl 11 or (x5 ushr 32 - 11)
            xs = x6 + xs
            x6 = x6 shl 11 or (x6 ushr 32 - 11)
            xt = x7 + xt
            x7 = x7 shl 11 or (x7 ushr 32 - 11)
            xc = xc xor xi
            xd = xd xor xj
            xe = xe xor xg
            xf = xf xor xh
            x8 = x8 xor xm
            x9 = x9 xor xn
            xa = xa xor xk
            xb = xb xor xl
            x4 = x4 xor xq
            x5 = x5 xor xr
            x6 = x6 xor xo
            x7 = x7 xor xp
            x0 = x0 xor xu
            x1 = x1 xor xv
            x2 = x2 xor xs
            x3 = x3 xor xt
            xj = xc + xj
            xc = xc shl 7 or (xc ushr 32 - 7)
            xi = xd + xi
            xd = xd shl 7 or (xd ushr 32 - 7)
            xh = xe + xh
            xe = xe shl 7 or (xe ushr 32 - 7)
            xg = xf + xg
            xf = xf shl 7 or (xf ushr 32 - 7)
            xn = x8 + xn
            x8 = x8 shl 7 or (x8 ushr 32 - 7)
            xm = x9 + xm
            x9 = x9 shl 7 or (x9 ushr 32 - 7)
            xl = xa + xl
            xa = xa shl 7 or (xa ushr 32 - 7)
            xk = xb + xk
            xb = xb shl 7 or (xb ushr 32 - 7)
            xr = x4 + xr
            x4 = x4 shl 7 or (x4 ushr 32 - 7)
            xq = x5 + xq
            x5 = x5 shl 7 or (x5 ushr 32 - 7)
            xp = x6 + xp
            x6 = x6 shl 7 or (x6 ushr 32 - 7)
            xo = x7 + xo
            x7 = x7 shl 7 or (x7 ushr 32 - 7)
            xv = x0 + xv
            x0 = x0 shl 7 or (x0 ushr 32 - 7)
            xu = x1 + xu
            x1 = x1 shl 7 or (x1 ushr 32 - 7)
            xt = x2 + xt
            x2 = x2 shl 7 or (x2 ushr 32 - 7)
            xs = x3 + xs
            x3 = x3 shl 7 or (x3 ushr 32 - 7)
            x4 = x4 xor xj
            x5 = x5 xor xi
            x6 = x6 xor xh
            x7 = x7 xor xg
            x0 = x0 xor xn
            x1 = x1 xor xm
            x2 = x2 xor xl
            x3 = x3 xor xk
            xc = xc xor xr
            xd = xd xor xq
            xe = xe xor xp
            xf = xf xor xo
            x8 = x8 xor xv
            x9 = x9 xor xu
            xa = xa xor xt
            xb = xb xor xs
            xh = x4 + xh
            x4 = x4 shl 11 or (x4 ushr 32 - 11)
            xg = x5 + xg
            x5 = x5 shl 11 or (x5 ushr 32 - 11)
            xj = x6 + xj
            x6 = x6 shl 11 or (x6 ushr 32 - 11)
            xi = x7 + xi
            x7 = x7 shl 11 or (x7 ushr 32 - 11)
            xl = x0 + xl
            x0 = x0 shl 11 or (x0 ushr 32 - 11)
            xk = x1 + xk
            x1 = x1 shl 11 or (x1 ushr 32 - 11)
            xn = x2 + xn
            x2 = x2 shl 11 or (x2 ushr 32 - 11)
            xm = x3 + xm
            x3 = x3 shl 11 or (x3 ushr 32 - 11)
            xp = xc + xp
            xc = xc shl 11 or (xc ushr 32 - 11)
            xo = xd + xo
            xd = xd shl 11 or (xd ushr 32 - 11)
            xr = xe + xr
            xe = xe shl 11 or (xe ushr 32 - 11)
            xq = xf + xq
            xf = xf shl 11 or (xf ushr 32 - 11)
            xt = x8 + xt
            x8 = x8 shl 11 or (x8 ushr 32 - 11)
            xs = x9 + xs
            x9 = x9 shl 11 or (x9 ushr 32 - 11)
            xv = xa + xv
            xa = xa shl 11 or (xa ushr 32 - 11)
            xu = xb + xu
            xb = xb shl 11 or (xb ushr 32 - 11)
            x0 = x0 xor xh
            x1 = x1 xor xg
            x2 = x2 xor xj
            x3 = x3 xor xi
            x4 = x4 xor xl
            x5 = x5 xor xk
            x6 = x6 xor xn
            x7 = x7 xor xm
            x8 = x8 xor xp
            x9 = x9 xor xo
            xa = xa xor xr
            xb = xb xor xq
            xc = xc xor xt
            xd = xd xor xs
            xe = xe xor xv
            xf = xf xor xu
        }
    }

    /** @see DigestEngine
     */
    override fun engineReset() {
        doReset()
    }

    /** @see DigestEngine
     */
    override fun processBlock(data: ByteArray) {
        inputBlock(data)
        sixteenRounds()
    }

    /** @see DigestEngine
     */
    override fun doPadding(out: ByteArray, off: Int) {
        var ptr = flush()
        val buf = blockBuffer
        buf[ptr++] = 0x80.toByte()
        while (ptr < 32) buf[ptr++] = 0x00
        inputBlock(buf)
        sixteenRounds()
        xv = xv xor 1
        for (j in 0..9) sixteenRounds()
        val dlen = digestLength
        encodeLEInt(x0, out, off + 0)
        encodeLEInt(x1, out, off + 4)
        encodeLEInt(x2, out, off + 8)
        encodeLEInt(x3, out, off + 12)
        encodeLEInt(x4, out, off + 16)
        encodeLEInt(x5, out, off + 20)
        encodeLEInt(x6, out, off + 24)
        if (dlen == 28) return
        encodeLEInt(x7, out, off + 28)
        if (dlen == 32) return
        encodeLEInt(x8, out, off + 32)
        encodeLEInt(x9, out, off + 36)
        encodeLEInt(xa, out, off + 40)
        encodeLEInt(xb, out, off + 44)
        if (dlen == 48) return
        encodeLEInt(xc, out, off + 48)
        encodeLEInt(xd, out, off + 52)
        encodeLEInt(xe, out, off + 56)
        encodeLEInt(xf, out, off + 60)
    }

    /** @see DigestEngine
     */
    override fun doInit() {
        doReset()
    }

    /**
     * Get the initial values.
     *
     * @return  the IV
     */
    abstract val iV: IntArray

    /** @see DigestEngine
     */
    val internalBlockLength: Int
        get() = 32/*
		 * From the CubeHash specification:
		 *
		 * << Applications such as HMAC that pad to a full block
		 *    of SHA-h input are required to pad to a full minimal
		 *    integral number of b-byte blocks for CubeHashr/b-h. >>
		 *
		 * Here, b = 32.
		 */

    /** @see Digest
     */
    override val blockLength: Int
        get() =/*
		 * From the CubeHash specification:
		 *
		 * << Applications such as HMAC that pad to a full block
		 *    of SHA-h input are required to pad to a full minimal
		 *    integral number of b-byte blocks for CubeHashr/b-h. >>
		 *
		 * Here, b = 32.
		 */
            32

    private fun doReset() {
        val iv = iV
        x0 = iv[0]
        x1 = iv[1]
        x2 = iv[2]
        x3 = iv[3]
        x4 = iv[4]
        x5 = iv[5]
        x6 = iv[6]
        x7 = iv[7]
        x8 = iv[8]
        x9 = iv[9]
        xa = iv[10]
        xb = iv[11]
        xc = iv[12]
        xd = iv[13]
        xe = iv[14]
        xf = iv[15]
        xg = iv[16]
        xh = iv[17]
        xi = iv[18]
        xj = iv[19]
        xk = iv[20]
        xl = iv[21]
        xm = iv[22]
        xn = iv[23]
        xo = iv[24]
        xp = iv[25]
        xq = iv[26]
        xr = iv[27]
        xs = iv[28]
        xt = iv[29]
        xu = iv[30]
        xv = iv[31]
    }

    /** @see DigestEngine
     */
    protected fun copyState(dst: CubeHashCore): Digest {
        dst.x0 = x0
        dst.x1 = x1
        dst.x2 = x2
        dst.x3 = x3
        dst.x4 = x4
        dst.x5 = x5
        dst.x6 = x6
        dst.x7 = x7
        dst.x8 = x8
        dst.x9 = x9
        dst.xa = xa
        dst.xb = xb
        dst.xc = xc
        dst.xd = xd
        dst.xe = xe
        dst.xf = xf
        dst.xg = xg
        dst.xh = xh
        dst.xi = xi
        dst.xj = xj
        dst.xk = xk
        dst.xl = xl
        dst.xm = xm
        dst.xn = xn
        dst.xo = xo
        dst.xp = xp
        dst.xq = xq
        dst.xr = xr
        dst.xs = xs
        dst.xt = xt
        dst.xu = xu
        dst.xv = xv
        return super.copyState(dst)
    }

    /** @see Digest
     */
    override fun toString(): String {
        return "CubeHash-" + (digestLength shl 3)
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