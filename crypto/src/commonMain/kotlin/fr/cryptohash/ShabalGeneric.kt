// $Id: ShabalGeneric.java 231 2010-06-16 21:46:06Z tp $
package fr.cryptohash

/**
 * This class implements Shabal for all output sizes from 32 to 512 bits
 * (inclusive, only multiples of 32 are supported). The output size must
 * be provided as parameter to the constructor. Alternatively, you may
 * use the [Shabal192], [Shabal224], [Shabal256],
 * [Shabal384] or [Shabal512] classes for size-specific
 * variants which offer a nullary constructor.
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
 * @version   $Revision: 231 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
open class ShabalGeneric private constructor() : Digest {
    private var outSizeW32 = 0
    private val buf: ByteArray
    private var ptr = 0
    private val state: IntArray
    private var W: Long = 0

    /**
     * Create the object. The output size must be a multiple of 32,
     * between 32 and 512 (inclusive).
     *
     * @param outSize   the intended output size
     */
    constructor(outSize: Int) : this() {
        if (outSize < 32 || outSize > 512 || outSize and 31 != 0) throw IllegalArgumentException(
            "invalid Shabal output size: $outSize"
        )
        outSizeW32 = outSize ushr 5
        reset()
    }

    override fun update(`in`: Byte) {
        buf[ptr++] = `in`
        if (ptr == 64) {
            core(buf, 0, 1)
            ptr = 0
        }
    }

    override fun update(inbuf: ByteArray) {
        update(inbuf, 0, inbuf.size)
    }

    override fun update(inbuf: ByteArray, off: Int, len: Int) {
        var off = off
        var len = len
        if (ptr != 0) {
            val rlen = 64 - ptr
            if (len < rlen) {
                inbuf.copyInto(buf, ptr, off, off + len)
                ptr += len
                return
            } else {
                inbuf.copyInto(buf, ptr, off, off + rlen)
                off += rlen
                len -= rlen
                core(buf, 0, 1)
            }
        }
        val num = len ushr 6
        if (num > 0) {
            core(inbuf, off, num)
            off += num shl 6
            len = len and 63
        }
        inbuf.copyInto(buf, 0, off, off + len)
        ptr = len
    }

    override val digestLength: Int
        get() = outSizeW32 shl 2

    override fun digest(): ByteArray {
        val n = digestLength
        val out = ByteArray(n)
        digest(out, 0, n)
        return out
    }

    override fun digest(inbuf: ByteArray): ByteArray {
        update(inbuf, 0, inbuf.size)
        return digest()
    }

    override fun digest(outbuf: ByteArray, off: Int, len: Int): Int {
        var len = len
        val dlen = digestLength
        if (len > dlen) len = dlen
        buf[ptr++] = 0x80.toByte()
        for (i in ptr..63) buf[i] = 0
        for (i in 0..3) {
            core(buf, 0, 1)
            W--
        }
        var j = 44 - (dlen ushr 2)
        var w = 0
        for (i in 0 until len) {
            if (i and 3 == 0) w = state[j++]
            outbuf[i] = w.toByte()
            w = w ushr 8
        }
        reset()
        return len
    }

    final override fun reset() {
        getIV(outSizeW32).copyInto(state, 0, 0, 44)
        W = 1
        ptr = 0
    }

    override fun copy(): Digest {
        val d = dup()
        d.outSizeW32 = outSizeW32
        buf.copyInto(d.buf, 0, 0, ptr)
        d.ptr = ptr
        state.copyInto(d.state, 0, 0, 44)
        d.W = W
        return d
    }

    /**
     * Create a new instance with the same parameters. This method
     * is invoked from [.copy].
     *
     * @return  the new instance
     */
    protected open fun dup(): ShabalGeneric {
        return ShabalGeneric()
    }

    override val blockLength: Int
        get() = 64

    private fun core(data: ByteArray, off: Int, num: Int) {
        var off = off
        var num = num
        var A0 = state[0]
        var A1 = state[1]
        var A2 = state[2]
        var A3 = state[3]
        var A4 = state[4]
        var A5 = state[5]
        var A6 = state[6]
        var A7 = state[7]
        var A8 = state[8]
        var A9 = state[9]
        var AA = state[10]
        var AB = state[11]
        var B0 = state[12]
        var B1 = state[13]
        var B2 = state[14]
        var B3 = state[15]
        var B4 = state[16]
        var B5 = state[17]
        var B6 = state[18]
        var B7 = state[19]
        var B8 = state[20]
        var B9 = state[21]
        var BA = state[22]
        var BB = state[23]
        var BC = state[24]
        var BD = state[25]
        var BE = state[26]
        var BF = state[27]
        var C0 = state[28]
        var C1 = state[29]
        var C2 = state[30]
        var C3 = state[31]
        var C4 = state[32]
        var C5 = state[33]
        var C6 = state[34]
        var C7 = state[35]
        var C8 = state[36]
        var C9 = state[37]
        var CA = state[38]
        var CB = state[39]
        var CC = state[40]
        var CD = state[41]
        var CE = state[42]
        var CF = state[43]
        while (num-- > 0) {
            val M0 = decodeLEInt(data, off + 0)
            B0 += M0
            B0 = B0 shl 17 or (B0 ushr 15)
            val M1 = decodeLEInt(data, off + 4)
            B1 += M1
            B1 = B1 shl 17 or (B1 ushr 15)
            val M2 = decodeLEInt(data, off + 8)
            B2 += M2
            B2 = B2 shl 17 or (B2 ushr 15)
            val M3 = decodeLEInt(data, off + 12)
            B3 += M3
            B3 = B3 shl 17 or (B3 ushr 15)
            val M4 = decodeLEInt(data, off + 16)
            B4 += M4
            B4 = B4 shl 17 or (B4 ushr 15)
            val M5 = decodeLEInt(data, off + 20)
            B5 += M5
            B5 = B5 shl 17 or (B5 ushr 15)
            val M6 = decodeLEInt(data, off + 24)
            B6 += M6
            B6 = B6 shl 17 or (B6 ushr 15)
            val M7 = decodeLEInt(data, off + 28)
            B7 += M7
            B7 = B7 shl 17 or (B7 ushr 15)
            val M8 = decodeLEInt(data, off + 32)
            B8 += M8
            B8 = B8 shl 17 or (B8 ushr 15)
            val M9 = decodeLEInt(data, off + 36)
            B9 += M9
            B9 = B9 shl 17 or (B9 ushr 15)
            val MA = decodeLEInt(data, off + 40)
            BA += MA
            BA = BA shl 17 or (BA ushr 15)
            val MB = decodeLEInt(data, off + 44)
            BB += MB
            BB = BB shl 17 or (BB ushr 15)
            val MC = decodeLEInt(data, off + 48)
            BC += MC
            BC = BC shl 17 or (BC ushr 15)
            val MD = decodeLEInt(data, off + 52)
            BD += MD
            BD = BD shl 17 or (BD ushr 15)
            val ME = decodeLEInt(data, off + 56)
            BE += ME
            BE = BE shl 17 or (BE ushr 15)
            val MF = decodeLEInt(data, off + 60)
            BF += MF
            BF = BF shl 17 or (BF ushr 15)
            off += 64
            A0 = A0 xor W.toInt()
            A1 = A1 xor (W ushr 32).toInt()
            W++
            A0 = ((A0 xor (AB shl 15 or (AB ushr 17)) * 5 xor C8) * 3
                    xor BD xor (B9 and B6.inv()) xor M0)
            B0 = (B0 shl 1 or (B0 ushr 31)).inv() xor A0
            A1 = ((A1 xor (A0 shl 15 or (A0 ushr 17)) * 5 xor C7) * 3
                    xor BE xor (BA and B7.inv()) xor M1)
            B1 = (B1 shl 1 or (B1 ushr 31)).inv() xor A1
            A2 = ((A2 xor (A1 shl 15 or (A1 ushr 17)) * 5 xor C6) * 3
                    xor BF xor (BB and B8.inv()) xor M2)
            B2 = (B2 shl 1 or (B2 ushr 31)).inv() xor A2
            A3 = ((A3 xor (A2 shl 15 or (A2 ushr 17)) * 5 xor C5) * 3
                    xor B0 xor (BC and B9.inv()) xor M3)
            B3 = (B3 shl 1 or (B3 ushr 31)).inv() xor A3
            A4 = ((A4 xor (A3 shl 15 or (A3 ushr 17)) * 5 xor C4) * 3
                    xor B1 xor (BD and BA.inv()) xor M4)
            B4 = (B4 shl 1 or (B4 ushr 31)).inv() xor A4
            A5 = ((A5 xor (A4 shl 15 or (A4 ushr 17)) * 5 xor C3) * 3
                    xor B2 xor (BE and BB.inv()) xor M5)
            B5 = (B5 shl 1 or (B5 ushr 31)).inv() xor A5
            A6 = ((A6 xor (A5 shl 15 or (A5 ushr 17)) * 5 xor C2) * 3
                    xor B3 xor (BF and BC.inv()) xor M6)
            B6 = (B6 shl 1 or (B6 ushr 31)).inv() xor A6
            A7 = ((A7 xor (A6 shl 15 or (A6 ushr 17)) * 5 xor C1) * 3
                    xor B4 xor (B0 and BD.inv()) xor M7)
            B7 = (B7 shl 1 or (B7 ushr 31)).inv() xor A7
            A8 = ((A8 xor (A7 shl 15 or (A7 ushr 17)) * 5 xor C0) * 3
                    xor B5 xor (B1 and BE.inv()) xor M8)
            B8 = (B8 shl 1 or (B8 ushr 31)).inv() xor A8
            A9 = ((A9 xor (A8 shl 15 or (A8 ushr 17)) * 5 xor CF) * 3
                    xor B6 xor (B2 and BF.inv()) xor M9)
            B9 = (B9 shl 1 or (B9 ushr 31)).inv() xor A9
            AA = ((AA xor (A9 shl 15 or (A9 ushr 17)) * 5 xor CE) * 3
                    xor B7 xor (B3 and B0.inv()) xor MA)
            BA = (BA shl 1 or (BA ushr 31)).inv() xor AA
            AB = ((AB xor (AA shl 15 or (AA ushr 17)) * 5 xor CD) * 3
                    xor B8 xor (B4 and B1.inv()) xor MB)
            BB = (BB shl 1 or (BB ushr 31)).inv() xor AB
            A0 = ((A0 xor (AB shl 15 or (AB ushr 17)) * 5 xor CC) * 3
                    xor B9 xor (B5 and B2.inv()) xor MC)
            BC = (BC shl 1 or (BC ushr 31)).inv() xor A0
            A1 = ((A1 xor (A0 shl 15 or (A0 ushr 17)) * 5 xor CB) * 3
                    xor BA xor (B6 and B3.inv()) xor MD)
            BD = (BD shl 1 or (BD ushr 31)).inv() xor A1
            A2 = ((A2 xor (A1 shl 15 or (A1 ushr 17)) * 5 xor CA) * 3
                    xor BB xor (B7 and B4.inv()) xor ME)
            BE = (BE shl 1 or (BE ushr 31)).inv() xor A2
            A3 = ((A3 xor (A2 shl 15 or (A2 ushr 17)) * 5 xor C9) * 3
                    xor BC xor (B8 and B5.inv()) xor MF)
            BF = (BF shl 1 or (BF ushr 31)).inv() xor A3
            A4 = ((A4 xor (A3 shl 15 or (A3 ushr 17)) * 5 xor C8) * 3
                    xor BD xor (B9 and B6.inv()) xor M0)
            B0 = (B0 shl 1 or (B0 ushr 31)).inv() xor A4
            A5 = ((A5 xor (A4 shl 15 or (A4 ushr 17)) * 5 xor C7) * 3
                    xor BE xor (BA and B7.inv()) xor M1)
            B1 = (B1 shl 1 or (B1 ushr 31)).inv() xor A5
            A6 = ((A6 xor (A5 shl 15 or (A5 ushr 17)) * 5 xor C6) * 3
                    xor BF xor (BB and B8.inv()) xor M2)
            B2 = (B2 shl 1 or (B2 ushr 31)).inv() xor A6
            A7 = ((A7 xor (A6 shl 15 or (A6 ushr 17)) * 5 xor C5) * 3
                    xor B0 xor (BC and B9.inv()) xor M3)
            B3 = (B3 shl 1 or (B3 ushr 31)).inv() xor A7
            A8 = ((A8 xor (A7 shl 15 or (A7 ushr 17)) * 5 xor C4) * 3
                    xor B1 xor (BD and BA.inv()) xor M4)
            B4 = (B4 shl 1 or (B4 ushr 31)).inv() xor A8
            A9 = ((A9 xor (A8 shl 15 or (A8 ushr 17)) * 5 xor C3) * 3
                    xor B2 xor (BE and BB.inv()) xor M5)
            B5 = (B5 shl 1 or (B5 ushr 31)).inv() xor A9
            AA = ((AA xor (A9 shl 15 or (A9 ushr 17)) * 5 xor C2) * 3
                    xor B3 xor (BF and BC.inv()) xor M6)
            B6 = (B6 shl 1 or (B6 ushr 31)).inv() xor AA
            AB = ((AB xor (AA shl 15 or (AA ushr 17)) * 5 xor C1) * 3
                    xor B4 xor (B0 and BD.inv()) xor M7)
            B7 = (B7 shl 1 or (B7 ushr 31)).inv() xor AB
            A0 = ((A0 xor (AB shl 15 or (AB ushr 17)) * 5 xor C0) * 3
                    xor B5 xor (B1 and BE.inv()) xor M8)
            B8 = (B8 shl 1 or (B8 ushr 31)).inv() xor A0
            A1 = ((A1 xor (A0 shl 15 or (A0 ushr 17)) * 5 xor CF) * 3
                    xor B6 xor (B2 and BF.inv()) xor M9)
            B9 = (B9 shl 1 or (B9 ushr 31)).inv() xor A1
            A2 = ((A2 xor (A1 shl 15 or (A1 ushr 17)) * 5 xor CE) * 3
                    xor B7 xor (B3 and B0.inv()) xor MA)
            BA = (BA shl 1 or (BA ushr 31)).inv() xor A2
            A3 = ((A3 xor (A2 shl 15 or (A2 ushr 17)) * 5 xor CD) * 3
                    xor B8 xor (B4 and B1.inv()) xor MB)
            BB = (BB shl 1 or (BB ushr 31)).inv() xor A3
            A4 = ((A4 xor (A3 shl 15 or (A3 ushr 17)) * 5 xor CC) * 3
                    xor B9 xor (B5 and B2.inv()) xor MC)
            BC = (BC shl 1 or (BC ushr 31)).inv() xor A4
            A5 = ((A5 xor (A4 shl 15 or (A4 ushr 17)) * 5 xor CB) * 3
                    xor BA xor (B6 and B3.inv()) xor MD)
            BD = (BD shl 1 or (BD ushr 31)).inv() xor A5
            A6 = ((A6 xor (A5 shl 15 or (A5 ushr 17)) * 5 xor CA) * 3
                    xor BB xor (B7 and B4.inv()) xor ME)
            BE = (BE shl 1 or (BE ushr 31)).inv() xor A6
            A7 = ((A7 xor (A6 shl 15 or (A6 ushr 17)) * 5 xor C9) * 3
                    xor BC xor (B8 and B5.inv()) xor MF)
            BF = (BF shl 1 or (BF ushr 31)).inv() xor A7
            A8 = ((A8 xor (A7 shl 15 or (A7 ushr 17)) * 5 xor C8) * 3
                    xor BD xor (B9 and B6.inv()) xor M0)
            B0 = (B0 shl 1 or (B0 ushr 31)).inv() xor A8
            A9 = ((A9 xor (A8 shl 15 or (A8 ushr 17)) * 5 xor C7) * 3
                    xor BE xor (BA and B7.inv()) xor M1)
            B1 = (B1 shl 1 or (B1 ushr 31)).inv() xor A9
            AA = ((AA xor (A9 shl 15 or (A9 ushr 17)) * 5 xor C6) * 3
                    xor BF xor (BB and B8.inv()) xor M2)
            B2 = (B2 shl 1 or (B2 ushr 31)).inv() xor AA
            AB = ((AB xor (AA shl 15 or (AA ushr 17)) * 5 xor C5) * 3
                    xor B0 xor (BC and B9.inv()) xor M3)
            B3 = (B3 shl 1 or (B3 ushr 31)).inv() xor AB
            A0 = ((A0 xor (AB shl 15 or (AB ushr 17)) * 5 xor C4) * 3
                    xor B1 xor (BD and BA.inv()) xor M4)
            B4 = (B4 shl 1 or (B4 ushr 31)).inv() xor A0
            A1 = ((A1 xor (A0 shl 15 or (A0 ushr 17)) * 5 xor C3) * 3
                    xor B2 xor (BE and BB.inv()) xor M5)
            B5 = (B5 shl 1 or (B5 ushr 31)).inv() xor A1
            A2 = ((A2 xor (A1 shl 15 or (A1 ushr 17)) * 5 xor C2) * 3
                    xor B3 xor (BF and BC.inv()) xor M6)
            B6 = (B6 shl 1 or (B6 ushr 31)).inv() xor A2
            A3 = ((A3 xor (A2 shl 15 or (A2 ushr 17)) * 5 xor C1) * 3
                    xor B4 xor (B0 and BD.inv()) xor M7)
            B7 = (B7 shl 1 or (B7 ushr 31)).inv() xor A3
            A4 = ((A4 xor (A3 shl 15 or (A3 ushr 17)) * 5 xor C0) * 3
                    xor B5 xor (B1 and BE.inv()) xor M8)
            B8 = (B8 shl 1 or (B8 ushr 31)).inv() xor A4
            A5 = ((A5 xor (A4 shl 15 or (A4 ushr 17)) * 5 xor CF) * 3
                    xor B6 xor (B2 and BF.inv()) xor M9)
            B9 = (B9 shl 1 or (B9 ushr 31)).inv() xor A5
            A6 = ((A6 xor (A5 shl 15 or (A5 ushr 17)) * 5 xor CE) * 3
                    xor B7 xor (B3 and B0.inv()) xor MA)
            BA = (BA shl 1 or (BA ushr 31)).inv() xor A6
            A7 = ((A7 xor (A6 shl 15 or (A6 ushr 17)) * 5 xor CD) * 3
                    xor B8 xor (B4 and B1.inv()) xor MB)
            BB = (BB shl 1 or (BB ushr 31)).inv() xor A7
            A8 = ((A8 xor (A7 shl 15 or (A7 ushr 17)) * 5 xor CC) * 3
                    xor B9 xor (B5 and B2.inv()) xor MC)
            BC = (BC shl 1 or (BC ushr 31)).inv() xor A8
            A9 = ((A9 xor (A8 shl 15 or (A8 ushr 17)) * 5 xor CB) * 3
                    xor BA xor (B6 and B3.inv()) xor MD)
            BD = (BD shl 1 or (BD ushr 31)).inv() xor A9
            AA = ((AA xor (A9 shl 15 or (A9 ushr 17)) * 5 xor CA) * 3
                    xor BB xor (B7 and B4.inv()) xor ME)
            BE = (BE shl 1 or (BE ushr 31)).inv() xor AA
            AB = ((AB xor (AA shl 15 or (AA ushr 17)) * 5 xor C9) * 3
                    xor BC xor (B8 and B5.inv()) xor MF)
            BF = (BF shl 1 or (BF ushr 31)).inv() xor AB
            AB += C6 + CA + CE
            AA += C5 + C9 + CD
            A9 += C4 + C8 + CC
            A8 += C3 + C7 + CB
            A7 += C2 + C6 + CA
            A6 += C1 + C5 + C9
            A5 += C0 + C4 + C8
            A4 += CF + C3 + C7
            A3 += CE + C2 + C6
            A2 += CD + C1 + C5
            A1 += CC + C0 + C4
            A0 += CB + CF + C3
            var tmp: Int
            tmp = B0
            B0 = C0 - M0
            C0 = tmp
            tmp = B1
            B1 = C1 - M1
            C1 = tmp
            tmp = B2
            B2 = C2 - M2
            C2 = tmp
            tmp = B3
            B3 = C3 - M3
            C3 = tmp
            tmp = B4
            B4 = C4 - M4
            C4 = tmp
            tmp = B5
            B5 = C5 - M5
            C5 = tmp
            tmp = B6
            B6 = C6 - M6
            C6 = tmp
            tmp = B7
            B7 = C7 - M7
            C7 = tmp
            tmp = B8
            B8 = C8 - M8
            C8 = tmp
            tmp = B9
            B9 = C9 - M9
            C9 = tmp
            tmp = BA
            BA = CA - MA
            CA = tmp
            tmp = BB
            BB = CB - MB
            CB = tmp
            tmp = BC
            BC = CC - MC
            CC = tmp
            tmp = BD
            BD = CD - MD
            CD = tmp
            tmp = BE
            BE = CE - ME
            CE = tmp
            tmp = BF
            BF = CF - MF
            CF = tmp
        }
        state[0] = A0
        state[1] = A1
        state[2] = A2
        state[3] = A3
        state[4] = A4
        state[5] = A5
        state[6] = A6
        state[7] = A7
        state[8] = A8
        state[9] = A9
        state[10] = AA
        state[11] = AB
        state[12] = B0
        state[13] = B1
        state[14] = B2
        state[15] = B3
        state[16] = B4
        state[17] = B5
        state[18] = B6
        state[19] = B7
        state[20] = B8
        state[21] = B9
        state[22] = BA
        state[23] = BB
        state[24] = BC
        state[25] = BD
        state[26] = BE
        state[27] = BF
        state[28] = C0
        state[29] = C1
        state[30] = C2
        state[31] = C3
        state[32] = C4
        state[33] = C5
        state[34] = C6
        state[35] = C7
        state[36] = C8
        state[37] = C9
        state[38] = CA
        state[39] = CB
        state[40] = CC
        state[41] = CD
        state[42] = CE
        state[43] = CF
    }

    override fun toString(): String {
        return "Shabal-" + (digestLength shl 3)
    }

    companion object {
        private val IVs = arrayOfNulls<IntArray>(16)
        private fun getIV(outSizeW32: Int): IntArray {
            var iv = IVs[outSizeW32 - 1]
            if (iv == null) {
                val outSize = outSizeW32 shl 5
                val sg = ShabalGeneric()
                for (i in 0..43) sg.state[i] = 0
                sg.W = -1L
                for (i in 0..15) {
                    sg.buf[(i shl 2) + 0] = (outSize + i).toByte()
                    sg.buf[(i shl 2) + 1] = (outSize + i ushr 8).toByte()
                }
                sg.core(sg.buf, 0, 1)
                for (i in 0..15) {
                    sg.buf[(i shl 2) + 0] = (outSize + i + 16).toByte()
                    sg.buf[(i shl 2) + 1] = (outSize + i + 16 ushr 8).toByte()
                }
                sg.core(sg.buf, 0, 1)
                IVs[outSizeW32 - 1] = sg.state
                iv = IVs[outSizeW32 - 1]
            }
            return iv!!
        }

        private fun decodeLEInt(data: ByteArray, off: Int): Int {
            return (data[off + 0].toInt() and 0xFF
                    or (data[off + 1].toInt() and 0xFF shl 8)
                    or (data[off + 2].toInt() and 0xFF shl 16)
                    or (data[off + 3].toInt() and 0xFF shl 24))
        }
    }

    init {
        buf = ByteArray(64)
        state = IntArray(44)
    }
}
