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
 * This class implements the Skein core with a 512-bit internal state
 * ("Skein-512" in the Skein specification terminology). This is used
 * for Skein-224, Skein-256, Skein-384 and Skein-512 (the SHA-3
 * candidates).
 *
 * @version   $Revision: 253 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
abstract class SkeinBigCore : Digest {
    private val buf: ByteArray
    private val tmpOut: ByteArray
    private var ptr = 0
    private val h: LongArray
    private var bcount: Long = 0

    override fun update(input: Byte) {
        if (ptr == blockLength) {
            val etype = if (bcount == 0L) 224 else 96
            bcount++
            ubi(etype, 0)
            buf[0] = input
            ptr = 1
        } else {
            buf[ptr++] = input
        }
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    @Suppress("NAME_SHADOWING")
    override fun update(input: ByteArray, offset: Int, length: Int) {
        var off = offset
        var len = length
        if (len <= 0) return
        val clen = blockLength - ptr
        if (len <= clen) {
            input.copyInto(buf, ptr, off, off + len)
            ptr += len
            return
        }
        if (clen != 0) {
            input.copyInto(buf, ptr, off, off + clen)
            off += clen
            len -= clen
        }
        while (true) {
            val etype = if (bcount == 0L) 224 else 96
            bcount++
            ubi(etype, 0)
            if (len <= blockLength) break
            input.copyInto(buf, 0, off, off + blockLength)
            off += blockLength
            len -= blockLength
        }
        input.copyInto(buf, 0, off, off + len)
        ptr = len
    }

    override fun digest(): ByteArray {
        val len = digestLength
        val out = ByteArray(len)
        digest(out, 0, len)
        return out
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input, 0, input.size)
        return digest()
    }

    @Suppress("NAME_SHADOWING")
    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        var len = length
        for (i in ptr until blockLength) buf[i] = 0x00
        ubi(if (bcount == 0L) 480 else 352, ptr)
        for (i in 0 until blockLength) buf[i] = 0x00
        bcount = 0L
        ubi(510, 8)
        for (i in 0..7) encodeLELong(h[i], tmpOut, i shl 3)
        val dlen = digestLength
        if (len > dlen) len = dlen
        tmpOut.copyInto(output, offset, 0, len)
        reset()
        return len
    }

    override fun reset() {
        ptr = 0
        val iv = initVal
        iv.copyInto(h, 0, 0, 8)
        bcount = 0L
    }

    override fun copy(): Digest {
        val dst = dup()
        buf.copyInto(dst.buf, 0, 0, ptr)
        dst.ptr = ptr
        h.copyInto(dst.h, 0, 0, 8)
        dst.bcount = bcount
        return dst
    }

    protected abstract fun dup(): SkeinBigCore

    /**
     * Get the initial value for this algorithm.
     *
     * @return  the initial value
     */
    protected abstract val initVal: LongArray

    private fun ubi(etype: Int, extra: Int) {
        val m0 = decodeLELong(buf, 0)
        val m1 = decodeLELong(buf, 8)
        val m2 = decodeLELong(buf, 16)
        val m3 = decodeLELong(buf, 24)
        val m4 = decodeLELong(buf, 32)
        val m5 = decodeLELong(buf, 40)
        val m6 = decodeLELong(buf, 48)
        val m7 = decodeLELong(buf, 56)
        var p0 = m0
        var p1 = m1
        var p2 = m2
        var p3 = m3
        var p4 = m4
        var p5 = m5
        var p6 = m6
        var p7 = m7
        h[8] = (h[0] xor h[1] xor (h[2] xor h[3])
                xor (h[4] xor h[5] xor (h[6] xor h[7])) xor 0x1BD11BDAA9FC1A22L)
        var t0 = (bcount shl 6) + extra.toLong()
        var t1 = (bcount ushr 58) + (etype.toLong() shl 55)
        var t2 = t0 xor t1
        run {
            var u = 0
            while (u <= 15) {
                h[u + 9] = h[u + 0]
                h[u + 10] = h[u + 1]
                h[u + 11] = h[u + 2]
                u += 3
            }
        }
        for (u in 0..8) {
            val s = u shl 1
            p0 += h[s + 0]
            p1 += h[s + 1]
            p2 += h[s + 2]
            p3 += h[s + 3]
            p4 += h[s + 4]
            p5 += h[s + 5] + t0
            p6 += h[s + 6] + t1
            p7 += h[s + 7] + s
            p0 += p1
            p1 = p1 shl 46 xor (p1 ushr 64 - 46) xor p0
            p2 += p3
            p3 = p3 shl 36 xor (p3 ushr 64 - 36) xor p2
            p4 += p5
            p5 = p5 shl 19 xor (p5 ushr 64 - 19) xor p4
            p6 += p7
            p7 = p7 shl 37 xor (p7 ushr 64 - 37) xor p6
            p2 += p1
            p1 = p1 shl 33 xor (p1 ushr 64 - 33) xor p2
            p4 += p7
            p7 = p7 shl 27 xor (p7 ushr 64 - 27) xor p4
            p6 += p5
            p5 = p5 shl 14 xor (p5 ushr 64 - 14) xor p6
            p0 += p3
            p3 = p3 shl 42 xor (p3 ushr 64 - 42) xor p0
            p4 += p1
            p1 = p1 shl 17 xor (p1 ushr 64 - 17) xor p4
            p6 += p3
            p3 = p3 shl 49 xor (p3 ushr 64 - 49) xor p6
            p0 += p5
            p5 = p5 shl 36 xor (p5 ushr 64 - 36) xor p0
            p2 += p7
            p7 = p7 shl 39 xor (p7 ushr 64 - 39) xor p2
            p6 += p1
            p1 = p1 shl 44 xor (p1 ushr 64 - 44) xor p6
            p0 += p7
            p7 = p7 shl 9 xor (p7 ushr 64 - 9) xor p0
            p2 += p5
            p5 = p5 shl 54 xor (p5 ushr 64 - 54) xor p2
            p4 += p3
            p3 = p3 shl 56 xor (p3 ushr 64 - 56) xor p4
            p0 += h[s + 1 + 0]
            p1 += h[s + 1 + 1]
            p2 += h[s + 1 + 2]
            p3 += h[s + 1 + 3]
            p4 += h[s + 1 + 4]
            p5 += h[s + 1 + 5] + t1
            p6 += h[s + 1 + 6] + t2
            p7 += h[s + 1 + 7] + s + 1
            p0 += p1
            p1 = p1 shl 39 xor (p1 ushr 64 - 39) xor p0
            p2 += p3
            p3 = p3 shl 30 xor (p3 ushr 64 - 30) xor p2
            p4 += p5
            p5 = p5 shl 34 xor (p5 ushr 64 - 34) xor p4
            p6 += p7
            p7 = p7 shl 24 xor (p7 ushr 64 - 24) xor p6
            p2 += p1
            p1 = p1 shl 13 xor (p1 ushr 64 - 13) xor p2
            p4 += p7
            p7 = p7 shl 50 xor (p7 ushr 64 - 50) xor p4
            p6 += p5
            p5 = p5 shl 10 xor (p5 ushr 64 - 10) xor p6
            p0 += p3
            p3 = p3 shl 17 xor (p3 ushr 64 - 17) xor p0
            p4 += p1
            p1 = p1 shl 25 xor (p1 ushr 64 - 25) xor p4
            p6 += p3
            p3 = p3 shl 29 xor (p3 ushr 64 - 29) xor p6
            p0 += p5
            p5 = p5 shl 39 xor (p5 ushr 64 - 39) xor p0
            p2 += p7
            p7 = p7 shl 43 xor (p7 ushr 64 - 43) xor p2
            p6 += p1
            p1 = p1 shl 8 xor (p1 ushr 64 - 8) xor p6
            p0 += p7
            p7 = p7 shl 35 xor (p7 ushr 64 - 35) xor p0
            p2 += p5
            p5 = p5 shl 56 xor (p5 ushr 64 - 56) xor p2
            p4 += p3
            p3 = p3 shl 22 xor (p3 ushr 64 - 22) xor p4
            val tmp = t2
            t2 = t1
            t1 = t0
            t0 = tmp
        }
        p0 += h[18 + 0]
        p1 += h[18 + 1]
        p2 += h[18 + 2]
        p3 += h[18 + 3]
        p4 += h[18 + 4]
        p5 += h[18 + 5] + t0
        p6 += h[18 + 6] + t1
        p7 += h[18 + 7] + 18
        h[0] = m0 xor p0
        h[1] = m1 xor p1
        h[2] = m2 xor p2
        h[3] = m3 xor p3
        h[4] = m4 xor p4
        h[5] = m5 xor p5
        h[6] = m6 xor p6
        h[7] = m7 xor p7
    }

    override fun toString(): String {
        return "Skein-" + (digestLength shl 3)
    }

    override val blockLength = 64

    companion object {

        private fun encodeLELong(`val`: Long, buf: ByteArray, off: Int) {
            buf[off + 0] = `val`.toByte()
            buf[off + 1] = (`val` ushr 8).toByte()
            buf[off + 2] = (`val` ushr 16).toByte()
            buf[off + 3] = (`val` ushr 24).toByte()
            buf[off + 4] = (`val` ushr 32).toByte()
            buf[off + 5] = (`val` ushr 40).toByte()
            buf[off + 6] = (`val` ushr 48).toByte()
            buf[off + 7] = (`val` ushr 56).toByte()
        }

        private fun decodeLELong(buf: ByteArray, off: Int): Long {
            return ((buf[off].toLong() and 0xFF)
                    or ((buf[off + 1].toLong() and 0xFF) shl 8)
                    or ((buf[off + 2].toLong() and 0xFF) shl 16)
                    or ((buf[off + 3].toLong() and 0xFF) shl 24)
                    or ((buf[off + 4].toLong() and 0xFF) shl 32)
                    or ((buf[off + 5].toLong() and 0xFF) shl 40)
                    or ((buf[off + 6].toLong() and 0xFF) shl 48)
                    or ((buf[off + 7].toLong() and 0xFF) shl 56))
        }
    }

    init {
        buf = ByteArray(blockLength)
        tmpOut = ByteArray(blockLength)
        h = LongArray(27)
        reset()
    }
}
