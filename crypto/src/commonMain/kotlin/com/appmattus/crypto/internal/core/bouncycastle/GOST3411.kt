/*
 * Copyright (c) 2000-2021 The Legion of the Bouncy Castle Inc. (https://www.bouncycastle.org)
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
package com.appmattus.crypto.internal.core.bouncycastle

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.encodeLELong

/**
 * implementation of GOST R 34.11-94
 */
internal class GOST3411() : Digest<GOST3411> {
    private val H = ByteArray(32)
    private val L = ByteArray(32)
    private val M = ByteArray(32)
    private val Sum = ByteArray(32)
    private val C = Array(4) { ByteArray(32) }
    private val xBuf = ByteArray(32)
    private var xBufOff = 0
    private var byteCount: Long = 0
    private val cipher = GOST28147Engine()

    init {
        cipher.initWithSbox(sBox)
        reset()
    }

    override fun update(input: Byte) {
        xBuf[xBufOff++] = input
        if (xBufOff == xBuf.size) {
            sumByteArray(xBuf) // calc sum M
            processBlock(xBuf, 0)
            xBufOff = 0
        }
        byteCount++
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        var inOff = offset
        var len = length
        while (xBufOff != 0 && len > 0) {
            update(input[inOff])
            inOff++
            len--
        }
        while (len > xBuf.size) {
            input.copyInto(xBuf, 0, inOff, inOff + xBuf.size)

            sumByteArray(xBuf) // calc sum M
            processBlock(xBuf, 0)
            inOff += xBuf.size
            len -= xBuf.size
            byteCount += xBuf.size.toLong()
        }

        // load in the remainder.
        while (len > 0) {
            update(input[inOff])
            inOff++
            len--
        }
    }

    // (i + 1 + 4(k - 1)) = 8i + k      i = 0-3, k = 1-8
    private val K = ByteArray(32)

    private fun P(`in`: ByteArray): ByteArray {
        for (k in 0..7) {
            K[4 * k] = `in`[k]
            K[1 + 4 * k] = `in`[8 + k]
            K[2 + 4 * k] = `in`[16 + k]
            K[3 + 4 * k] = `in`[24 + k]
        }
        return K
    }

    //A (x) = (x0 ^ x1) || x3 || x2 || x1
    var a = ByteArray(8)
    private fun A(`in`: ByteArray): ByteArray {
        for (j in 0..7) {
            a[j] = (`in`[j].toInt() xor `in`[j + 8].toInt()).toByte()
        }
        `in`.copyInto(`in`, 0, 8, 8 + 24)
        a.copyInto(`in`, 24, 0, 8)
        return `in`
    }

    //Encrypt function, ECB mode
    private fun E(key: ByteArray, s: ByteArray, sOff: Int, `in`: ByteArray, inOff: Int) {
        cipher.initWithKey(true, key)
        cipher.processBlock(`in`, inOff, s, sOff)
    }

    // (in:) n16||..||n1 ==> (out:) n1^n2^n3^n4^n13^n16||n16||..||n2
    var wS = ShortArray(16)
    var w_S = ShortArray(16)
    private fun fw(`in`: ByteArray) {
        cpyBytesToShort(`in`, wS)
        w_S[15] = (wS[0].toInt() xor wS[1].toInt() xor wS[2].toInt() xor wS[3].toInt() xor wS[12].toInt() xor wS[15].toInt()).toShort()
        wS.copyInto(w_S, 0, 1, 1 + 15)
        cpyShortToBytes(w_S, `in`)
    }

    // block processing
    var S = ByteArray(32)
    var U = ByteArray(32)
    var V = ByteArray(32)
    var W = ByteArray(32)
    protected fun processBlock(`in`: ByteArray, inOff: Int) {
        `in`.copyInto(M, 0, inOff, inOff + 32)

        //key step 1

        // H = h3 || h2 || h1 || h0
        // S = s3 || s2 || s1 || s0
        H.copyInto(U, 0, 0, 32)
        M.copyInto(V, 0, 0, 32)
        for (j in 0..31) {
            W[j] = (U[j].toInt() xor V[j].toInt()).toByte()
        }
        // Encrypt gost28147-ECB
        E(P(W), S, 0, H, 0) // s0 = EK0 [h0]

        //keys step 2,3,4
        for (i in 1..3) {
            val tmpA = A(U)
            for (j in 0..31) {
                U[j] = (tmpA[j].toInt() xor C[i][j].toInt()).toByte()
            }
            V = A(A(V))
            for (j in 0..31) {
                W[j] = (U[j].toInt() xor V[j].toInt()).toByte()
            }
            // Encrypt gost28147-ECB
            E(P(W), S, i * 8, H, i * 8) // si = EKi [hi]
        }

        // x(M, H) = y61(H^y(M^y12(S)))
        for (n in 0..11) {
            fw(S)
        }
        for (n in 0..31) {
            S[n] = (S[n].toInt() xor M[n].toInt()).toByte()
        }
        fw(S)
        for (n in 0..31) {
            S[n] = (H[n].toInt() xor S[n].toInt()).toByte()
        }
        for (n in 0..60) {
            fw(S)
        }
        S.copyInto(H, 0, 0, H.size)
    }

    private fun finish() {
        // get length into L (byteCount * 8 = bitCount)
        encodeLELong(byteCount * 8, L, 0)

        while (xBufOff != 0) {
            update(0.toByte())
        }
        processBlock(L, 0)
        processBlock(Sum, 0)
    }

    fun doFinal(
        out: ByteArray,
        outOff: Int
    ): Int {
        finish()
        H.copyInto(out, outOff, 0, H.size)
        reset()
        return digestLength
    }

    override fun reset() {
        byteCount = 0
        xBufOff = 0
        for (i in H.indices) {
            H[i] = 0 // start vector H
        }
        for (i in L.indices) {
            L[i] = 0
        }
        for (i in M.indices) {
            M[i] = 0
        }
        for (i in C[1].indices) {
            C[1][i] = 0 // real index C = +1 because index array with 0.
        }
        for (i in C[3].indices) {
            C[3][i] = 0
        }
        for (i in Sum.indices) {
            Sum[i] = 0
        }
        for (i in xBuf.indices) {
            xBuf[i] = 0
        }
        C2.copyInto(C[2], 0, 0, C2.size)
    }

    //  256 bitsblock modul -> (Sum + a mod (2^256))
    private fun sumByteArray(`in`: ByteArray) {
        var carry = 0
        for (i in Sum.indices) {
            val sum: Int = (Sum[i].toInt() and 0xff) + (`in`[i].toInt() and 0xff) + carry
            Sum[i] = sum.toByte()
            carry = sum ushr 8
        }
    }

    private fun cpyBytesToShort(S: ByteArray, wS: ShortArray) {
        for (i in 0 until S.size / 2) {
            wS[i] = (S[i * 2 + 1].toInt() shl 8 and 0xFF00 or (S[i * 2].toInt() and 0xFF)).toShort()
        }
    }

    private fun cpyShortToBytes(wS: ShortArray, S: ByteArray) {
        for (i in 0 until S.size / 2) {
            S[i * 2 + 1] = (wS[i].toInt() shr 8).toByte()
            S[i * 2] = wS[i].toByte()
        }
    }

    companion object {

        /**
         * reset the chaining variables to the IV values.
         */
        private val C2 = byteArrayOf(
            0x00, 0xFF.toByte(), 0x00, 0xFF.toByte(), 0x00, 0xFF.toByte(), 0x00, 0xFF.toByte(),
            0xFF.toByte(), 0x00, 0xFF.toByte(), 0x00, 0xFF.toByte(), 0x00, 0xFF.toByte(), 0x00,
            0x00, 0xFF.toByte(), 0xFF.toByte(), 0x00, 0xFF.toByte(), 0x00, 0x00, 0xFF.toByte(),
            0xFF.toByte(), 0x00, 0x00, 0x00, 0xFF.toByte(), 0xFF.toByte(), 0x00, 0xFF.toByte()
        )

        private val sBox = byteArrayOf(
            0x0A, 0x04, 0x05, 0x06, 0x08, 0x01, 0x03, 0x07, 0x0D, 0x0C, 0x0E, 0x00, 0x09, 0x02, 0x0B, 0x0F,
            0x05, 0x0F, 0x04, 0x00, 0x02, 0x0D, 0x0B, 0x09, 0x01, 0x07, 0x06, 0x03, 0x0C, 0x0E, 0x0A, 0x08,
            0x07, 0x0F, 0x0C, 0x0E, 0x09, 0x04, 0x01, 0x00, 0x03, 0x0B, 0x05, 0x02, 0x06, 0x0A, 0x08, 0x0D,
            0x04, 0x0A, 0x07, 0x0C, 0x00, 0x0F, 0x02, 0x08, 0x0E, 0x01, 0x06, 0x05, 0x0D, 0x0B, 0x09, 0x03,
            0x07, 0x06, 0x04, 0x0B, 0x09, 0x0C, 0x02, 0x0A, 0x01, 0x08, 0x00, 0x0E, 0x0F, 0x0D, 0x03, 0x05,
            0x07, 0x06, 0x02, 0x04, 0x0D, 0x09, 0x0F, 0x00, 0x0A, 0x01, 0x05, 0x0B, 0x08, 0x0E, 0x0C, 0x03,
            0x0D, 0x0E, 0x04, 0x01, 0x07, 0x00, 0x05, 0x0A, 0x03, 0x0C, 0x08, 0x0F, 0x06, 0x02, 0x09, 0x0B,
            0x01, 0x03, 0x0A, 0x09, 0x05, 0x0B, 0x04, 0x0F, 0x08, 0x06, 0x07, 0x0E, 0x0D, 0x00, 0x02, 0x0C
        )
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    override fun digest(): ByteArray {
        val result = ByteArray(digestLength)
        doFinal(result, 0)
        reset()
        return result
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        val digest = digest()

        if (length < digest.size) throw IllegalArgumentException("partial digests not returned")
        if (output.size - offset < digest.size) throw IllegalArgumentException("insufficient space in the output buffer to store the digest")

        digest.copyInto(output, offset, 0, digest.size)

        return digest.size
    }

    override val digestLength: Int
        get() = 32

    override val blockLength: Int
        get() = Algorithm.GOST3411_94.blockLength

    override fun toString() = Algorithm.GOST3411_94.algorithmName

    override fun copy(): GOST3411 {
        return GOST3411(this)
    }

    /**
     * Copy constructor.  This will copy the state of the provided
     * message digest.
     */
    private constructor(t: GOST3411) : this() {
        reset(t)
    }

    fun reset(t: GOST3411) {
        cipher.initWithSbox(sBox)
        reset()
        t.H.copyInto(H, 0, 0, t.H.size)
        t.L.copyInto(L, 0, 0, t.L.size)
        t.M.copyInto(M, 0, 0, t.M.size)
        t.Sum.copyInto(Sum, 0, 0, t.Sum.size)
        t.C[1].copyInto(C[1], 0, 0, t.C[1].size)
        t.C[2].copyInto(C[2], 0, 0, t.C[2].size)
        t.C[3].copyInto(C[3], 0, 0, t.C[3].size)
        t.xBuf.copyInto(xBuf, 0, 0, t.xBuf.size)
        xBufOff = t.xBufOff
        byteCount = t.byteCount
    }
}
