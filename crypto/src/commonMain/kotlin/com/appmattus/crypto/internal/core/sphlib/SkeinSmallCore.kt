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

package com.appmattus.crypto.internal.core.sphlib

import com.appmattus.crypto.Digest

/**
 * This class implements the Skein core function when used with a
 * 256-bit internal state ("Skein-256" in the Skein specification
 * terminology). This class is not currently used, since the recommended
 * parameters for the SHA-3 competition call for a 512-bit internal
 * state ("Skein-512") for all output sizes (224, 256, 384 and 512
 * bits).
 *
 * @version   $Revision: 253 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
internal abstract class SkeinSmallCore<D : SkeinSmallCore<D>>() : Digest<D> {
    private val buf: ByteArray
    private val tmpOut: ByteArray
    private var ptr = 0
    private var h0: Long = 0
    private var h1: Long = 0
    private var h2: Long = 0
    private var h3: Long = 0
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

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        var len = length
        for (i in ptr until blockLength) buf[i] = 0x00
        ubi(if (bcount == 0L) 480 else 352, ptr)
        for (i in 0 until blockLength) buf[i] = 0x00
        bcount = 0L
        ubi(510, 8)
        encodeLELong(h0, tmpOut, 0)
        encodeLELong(h1, tmpOut, 8)
        encodeLELong(h2, tmpOut, 16)
        encodeLELong(h3, tmpOut, 24)
        val dlen = digestLength
        if (len > dlen) len = dlen
        tmpOut.copyInto(output, offset, 0, len)
        reset()
        return len
    }

    override fun reset() {
        ptr = 0
        val iv = initVal
        h0 = iv[0]
        h1 = iv[1]
        h2 = iv[2]
        h3 = iv[3]
        bcount = 0L
    }

    override fun copy(): D {
        val dst = dup()
        buf.copyInto(dst.buf, 0, 0, ptr)
        dst.ptr = ptr
        dst.h0 = h0
        dst.h1 = h1
        dst.h2 = h2
        dst.h3 = h3
        dst.bcount = bcount
        return dst
    }

    protected abstract fun dup(): D

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
        var p0 = m0
        var p1 = m1
        var p2 = m2
        var p3 = m3
        val h4 = h0 xor h1 xor (h2 xor h3) xor 0x1BD11BDAA9FC1A22L
        val t0 = (bcount shl 5) + extra.toLong()
        val t1 = (bcount ushr 59) + (etype.toLong() shl 55)
        val t2 = t0 xor t1
        p0 += h0
        p1 += h1 + t0
        p2 += h2 + t1
        p3 += h3 + 0L
        p0 += p1
        p1 = p1 shl 14 xor (p1 ushr 64 - 14) xor p0
        p2 += p3
        p3 = p3 shl 16 xor (p3 ushr 64 - 16) xor p2
        p0 += p3
        p3 = p3 shl 52 xor (p3 ushr 64 - 52) xor p0
        p2 += p1
        p1 = p1 shl 57 xor (p1 ushr 64 - 57) xor p2
        p0 += p1
        p1 = p1 shl 23 xor (p1 ushr 64 - 23) xor p0
        p2 += p3
        p3 = p3 shl 40 xor (p3 ushr 64 - 40) xor p2
        p0 += p3
        p3 = p3 shl 5 xor (p3 ushr 64 - 5) xor p0
        p2 += p1
        p1 = p1 shl 37 xor (p1 ushr 64 - 37) xor p2
        p0 += h1
        p1 += h2 + t1
        p2 += h3 + t2
        p3 += h4 + 1L
        p0 += p1
        p1 = p1 shl 25 xor (p1 ushr 64 - 25) xor p0
        p2 += p3
        p3 = p3 shl 33 xor (p3 ushr 64 - 33) xor p2
        p0 += p3
        p3 = p3 shl 46 xor (p3 ushr 64 - 46) xor p0
        p2 += p1
        p1 = p1 shl 12 xor (p1 ushr 64 - 12) xor p2
        p0 += p1
        p1 = p1 shl 58 xor (p1 ushr 64 - 58) xor p0
        p2 += p3
        p3 = p3 shl 22 xor (p3 ushr 64 - 22) xor p2
        p0 += p3
        p3 = p3 shl 32 xor (p3 ushr 64 - 32) xor p0
        p2 += p1
        p1 = p1 shl 32 xor (p1 ushr 64 - 32) xor p2
        p0 += h2
        p1 += h3 + t2
        p2 += h4 + t0
        p3 += h0 + 2L
        p0 += p1
        p1 = p1 shl 14 xor (p1 ushr 64 - 14) xor p0
        p2 += p3
        p3 = p3 shl 16 xor (p3 ushr 64 - 16) xor p2
        p0 += p3
        p3 = p3 shl 52 xor (p3 ushr 64 - 52) xor p0
        p2 += p1
        p1 = p1 shl 57 xor (p1 ushr 64 - 57) xor p2
        p0 += p1
        p1 = p1 shl 23 xor (p1 ushr 64 - 23) xor p0
        p2 += p3
        p3 = p3 shl 40 xor (p3 ushr 64 - 40) xor p2
        p0 += p3
        p3 = p3 shl 5 xor (p3 ushr 64 - 5) xor p0
        p2 += p1
        p1 = p1 shl 37 xor (p1 ushr 64 - 37) xor p2
        p0 += h3
        p1 += h4 + t0
        p2 += h0 + t1
        p3 += h1 + 3L
        p0 += p1
        p1 = p1 shl 25 xor (p1 ushr 64 - 25) xor p0
        p2 += p3
        p3 = p3 shl 33 xor (p3 ushr 64 - 33) xor p2
        p0 += p3
        p3 = p3 shl 46 xor (p3 ushr 64 - 46) xor p0
        p2 += p1
        p1 = p1 shl 12 xor (p1 ushr 64 - 12) xor p2
        p0 += p1
        p1 = p1 shl 58 xor (p1 ushr 64 - 58) xor p0
        p2 += p3
        p3 = p3 shl 22 xor (p3 ushr 64 - 22) xor p2
        p0 += p3
        p3 = p3 shl 32 xor (p3 ushr 64 - 32) xor p0
        p2 += p1
        p1 = p1 shl 32 xor (p1 ushr 64 - 32) xor p2
        p0 += h4
        p1 += h0 + t1
        p2 += h1 + t2
        p3 += h2 + 4L
        p0 += p1
        p1 = p1 shl 14 xor (p1 ushr 64 - 14) xor p0
        p2 += p3
        p3 = p3 shl 16 xor (p3 ushr 64 - 16) xor p2
        p0 += p3
        p3 = p3 shl 52 xor (p3 ushr 64 - 52) xor p0
        p2 += p1
        p1 = p1 shl 57 xor (p1 ushr 64 - 57) xor p2
        p0 += p1
        p1 = p1 shl 23 xor (p1 ushr 64 - 23) xor p0
        p2 += p3
        p3 = p3 shl 40 xor (p3 ushr 64 - 40) xor p2
        p0 += p3
        p3 = p3 shl 5 xor (p3 ushr 64 - 5) xor p0
        p2 += p1
        p1 = p1 shl 37 xor (p1 ushr 64 - 37) xor p2
        p0 += h0
        p1 += h1 + t2
        p2 += h2 + t0
        p3 += h3 + 5L
        p0 += p1
        p1 = p1 shl 25 xor (p1 ushr 64 - 25) xor p0
        p2 += p3
        p3 = p3 shl 33 xor (p3 ushr 64 - 33) xor p2
        p0 += p3
        p3 = p3 shl 46 xor (p3 ushr 64 - 46) xor p0
        p2 += p1
        p1 = p1 shl 12 xor (p1 ushr 64 - 12) xor p2
        p0 += p1
        p1 = p1 shl 58 xor (p1 ushr 64 - 58) xor p0
        p2 += p3
        p3 = p3 shl 22 xor (p3 ushr 64 - 22) xor p2
        p0 += p3
        p3 = p3 shl 32 xor (p3 ushr 64 - 32) xor p0
        p2 += p1
        p1 = p1 shl 32 xor (p1 ushr 64 - 32) xor p2
        p0 += h1
        p1 += h2 + t0
        p2 += h3 + t1
        p3 += h4 + 6L
        p0 += p1
        p1 = p1 shl 14 xor (p1 ushr 64 - 14) xor p0
        p2 += p3
        p3 = p3 shl 16 xor (p3 ushr 64 - 16) xor p2
        p0 += p3
        p3 = p3 shl 52 xor (p3 ushr 64 - 52) xor p0
        p2 += p1
        p1 = p1 shl 57 xor (p1 ushr 64 - 57) xor p2
        p0 += p1
        p1 = p1 shl 23 xor (p1 ushr 64 - 23) xor p0
        p2 += p3
        p3 = p3 shl 40 xor (p3 ushr 64 - 40) xor p2
        p0 += p3
        p3 = p3 shl 5 xor (p3 ushr 64 - 5) xor p0
        p2 += p1
        p1 = p1 shl 37 xor (p1 ushr 64 - 37) xor p2
        p0 += h2
        p1 += h3 + t1
        p2 += h4 + t2
        p3 += h0 + 7L
        p0 += p1
        p1 = p1 shl 25 xor (p1 ushr 64 - 25) xor p0
        p2 += p3
        p3 = p3 shl 33 xor (p3 ushr 64 - 33) xor p2
        p0 += p3
        p3 = p3 shl 46 xor (p3 ushr 64 - 46) xor p0
        p2 += p1
        p1 = p1 shl 12 xor (p1 ushr 64 - 12) xor p2
        p0 += p1
        p1 = p1 shl 58 xor (p1 ushr 64 - 58) xor p0
        p2 += p3
        p3 = p3 shl 22 xor (p3 ushr 64 - 22) xor p2
        p0 += p3
        p3 = p3 shl 32 xor (p3 ushr 64 - 32) xor p0
        p2 += p1
        p1 = p1 shl 32 xor (p1 ushr 64 - 32) xor p2
        p0 += h3
        p1 += h4 + t2
        p2 += h0 + t0
        p3 += h1 + 8L
        p0 += p1
        p1 = p1 shl 14 xor (p1 ushr 64 - 14) xor p0
        p2 += p3
        p3 = p3 shl 16 xor (p3 ushr 64 - 16) xor p2
        p0 += p3
        p3 = p3 shl 52 xor (p3 ushr 64 - 52) xor p0
        p2 += p1
        p1 = p1 shl 57 xor (p1 ushr 64 - 57) xor p2
        p0 += p1
        p1 = p1 shl 23 xor (p1 ushr 64 - 23) xor p0
        p2 += p3
        p3 = p3 shl 40 xor (p3 ushr 64 - 40) xor p2
        p0 += p3
        p3 = p3 shl 5 xor (p3 ushr 64 - 5) xor p0
        p2 += p1
        p1 = p1 shl 37 xor (p1 ushr 64 - 37) xor p2
        p0 += h4
        p1 += h0 + t0
        p2 += h1 + t1
        p3 += h2 + 9L
        p0 += p1
        p1 = p1 shl 25 xor (p1 ushr 64 - 25) xor p0
        p2 += p3
        p3 = p3 shl 33 xor (p3 ushr 64 - 33) xor p2
        p0 += p3
        p3 = p3 shl 46 xor (p3 ushr 64 - 46) xor p0
        p2 += p1
        p1 = p1 shl 12 xor (p1 ushr 64 - 12) xor p2
        p0 += p1
        p1 = p1 shl 58 xor (p1 ushr 64 - 58) xor p0
        p2 += p3
        p3 = p3 shl 22 xor (p3 ushr 64 - 22) xor p2
        p0 += p3
        p3 = p3 shl 32 xor (p3 ushr 64 - 32) xor p0
        p2 += p1
        p1 = p1 shl 32 xor (p1 ushr 64 - 32) xor p2
        p0 += h0
        p1 += h1 + t1
        p2 += h2 + t2
        p3 += h3 + 10L
        p0 += p1
        p1 = p1 shl 14 xor (p1 ushr 64 - 14) xor p0
        p2 += p3
        p3 = p3 shl 16 xor (p3 ushr 64 - 16) xor p2
        p0 += p3
        p3 = p3 shl 52 xor (p3 ushr 64 - 52) xor p0
        p2 += p1
        p1 = p1 shl 57 xor (p1 ushr 64 - 57) xor p2
        p0 += p1
        p1 = p1 shl 23 xor (p1 ushr 64 - 23) xor p0
        p2 += p3
        p3 = p3 shl 40 xor (p3 ushr 64 - 40) xor p2
        p0 += p3
        p3 = p3 shl 5 xor (p3 ushr 64 - 5) xor p0
        p2 += p1
        p1 = p1 shl 37 xor (p1 ushr 64 - 37) xor p2
        p0 += h1
        p1 += h2 + t2
        p2 += h3 + t0
        p3 += h4 + 11L
        p0 += p1
        p1 = p1 shl 25 xor (p1 ushr 64 - 25) xor p0
        p2 += p3
        p3 = p3 shl 33 xor (p3 ushr 64 - 33) xor p2
        p0 += p3
        p3 = p3 shl 46 xor (p3 ushr 64 - 46) xor p0
        p2 += p1
        p1 = p1 shl 12 xor (p1 ushr 64 - 12) xor p2
        p0 += p1
        p1 = p1 shl 58 xor (p1 ushr 64 - 58) xor p0
        p2 += p3
        p3 = p3 shl 22 xor (p3 ushr 64 - 22) xor p2
        p0 += p3
        p3 = p3 shl 32 xor (p3 ushr 64 - 32) xor p0
        p2 += p1
        p1 = p1 shl 32 xor (p1 ushr 64 - 32) xor p2
        p0 += h2
        p1 += h3 + t0
        p2 += h4 + t1
        p3 += h0 + 12L
        p0 += p1
        p1 = p1 shl 14 xor (p1 ushr 64 - 14) xor p0
        p2 += p3
        p3 = p3 shl 16 xor (p3 ushr 64 - 16) xor p2
        p0 += p3
        p3 = p3 shl 52 xor (p3 ushr 64 - 52) xor p0
        p2 += p1
        p1 = p1 shl 57 xor (p1 ushr 64 - 57) xor p2
        p0 += p1
        p1 = p1 shl 23 xor (p1 ushr 64 - 23) xor p0
        p2 += p3
        p3 = p3 shl 40 xor (p3 ushr 64 - 40) xor p2
        p0 += p3
        p3 = p3 shl 5 xor (p3 ushr 64 - 5) xor p0
        p2 += p1
        p1 = p1 shl 37 xor (p1 ushr 64 - 37) xor p2
        p0 += h3
        p1 += h4 + t1
        p2 += h0 + t2
        p3 += h1 + 13L
        p0 += p1
        p1 = p1 shl 25 xor (p1 ushr 64 - 25) xor p0
        p2 += p3
        p3 = p3 shl 33 xor (p3 ushr 64 - 33) xor p2
        p0 += p3
        p3 = p3 shl 46 xor (p3 ushr 64 - 46) xor p0
        p2 += p1
        p1 = p1 shl 12 xor (p1 ushr 64 - 12) xor p2
        p0 += p1
        p1 = p1 shl 58 xor (p1 ushr 64 - 58) xor p0
        p2 += p3
        p3 = p3 shl 22 xor (p3 ushr 64 - 22) xor p2
        p0 += p3
        p3 = p3 shl 32 xor (p3 ushr 64 - 32) xor p0
        p2 += p1
        p1 = p1 shl 32 xor (p1 ushr 64 - 32) xor p2
        p0 += h4
        p1 += h0 + t2
        p2 += h1 + t0
        p3 += h2 + 14L
        p0 += p1
        p1 = p1 shl 14 xor (p1 ushr 64 - 14) xor p0
        p2 += p3
        p3 = p3 shl 16 xor (p3 ushr 64 - 16) xor p2
        p0 += p3
        p3 = p3 shl 52 xor (p3 ushr 64 - 52) xor p0
        p2 += p1
        p1 = p1 shl 57 xor (p1 ushr 64 - 57) xor p2
        p0 += p1
        p1 = p1 shl 23 xor (p1 ushr 64 - 23) xor p0
        p2 += p3
        p3 = p3 shl 40 xor (p3 ushr 64 - 40) xor p2
        p0 += p3
        p3 = p3 shl 5 xor (p3 ushr 64 - 5) xor p0
        p2 += p1
        p1 = p1 shl 37 xor (p1 ushr 64 - 37) xor p2
        p0 += h0
        p1 += h1 + t0
        p2 += h2 + t1
        p3 += h3 + 15L
        p0 += p1
        p1 = p1 shl 25 xor (p1 ushr 64 - 25) xor p0
        p2 += p3
        p3 = p3 shl 33 xor (p3 ushr 64 - 33) xor p2
        p0 += p3
        p3 = p3 shl 46 xor (p3 ushr 64 - 46) xor p0
        p2 += p1
        p1 = p1 shl 12 xor (p1 ushr 64 - 12) xor p2
        p0 += p1
        p1 = p1 shl 58 xor (p1 ushr 64 - 58) xor p0
        p2 += p3
        p3 = p3 shl 22 xor (p3 ushr 64 - 22) xor p2
        p0 += p3
        p3 = p3 shl 32 xor (p3 ushr 64 - 32) xor p0
        p2 += p1
        p1 = p1 shl 32 xor (p1 ushr 64 - 32) xor p2
        p0 += h1
        p1 += h2 + t1
        p2 += h3 + t2
        p3 += h4 + 16L
        p0 += p1
        p1 = p1 shl 14 xor (p1 ushr 64 - 14) xor p0
        p2 += p3
        p3 = p3 shl 16 xor (p3 ushr 64 - 16) xor p2
        p0 += p3
        p3 = p3 shl 52 xor (p3 ushr 64 - 52) xor p0
        p2 += p1
        p1 = p1 shl 57 xor (p1 ushr 64 - 57) xor p2
        p0 += p1
        p1 = p1 shl 23 xor (p1 ushr 64 - 23) xor p0
        p2 += p3
        p3 = p3 shl 40 xor (p3 ushr 64 - 40) xor p2
        p0 += p3
        p3 = p3 shl 5 xor (p3 ushr 64 - 5) xor p0
        p2 += p1
        p1 = p1 shl 37 xor (p1 ushr 64 - 37) xor p2
        p0 += h2
        p1 += h3 + t2
        p2 += h4 + t0
        p3 += h0 + 17L
        p0 += p1
        p1 = p1 shl 25 xor (p1 ushr 64 - 25) xor p0
        p2 += p3
        p3 = p3 shl 33 xor (p3 ushr 64 - 33) xor p2
        p0 += p3
        p3 = p3 shl 46 xor (p3 ushr 64 - 46) xor p0
        p2 += p1
        p1 = p1 shl 12 xor (p1 ushr 64 - 12) xor p2
        p0 += p1
        p1 = p1 shl 58 xor (p1 ushr 64 - 58) xor p0
        p2 += p3
        p3 = p3 shl 22 xor (p3 ushr 64 - 22) xor p2
        p0 += p3
        p3 = p3 shl 32 xor (p3 ushr 64 - 32) xor p0
        p2 += p1
        p1 = p1 shl 32 xor (p1 ushr 64 - 32) xor p2
        p0 += h3
        p1 += h4 + t0
        p2 += h0 + t1
        p3 += h1 + 18L
        h0 = m0 xor p0
        h1 = m1 xor p1
        h2 = m2 xor p2
        h3 = m3 xor p3
    }

    override fun toString(): String {
        return "Skein-" + (digestLength shl 3)
    }

    override val blockLength = 32

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
        reset()
    }
}
