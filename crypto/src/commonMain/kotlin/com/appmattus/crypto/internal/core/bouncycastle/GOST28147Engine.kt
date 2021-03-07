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

import com.appmattus.crypto.internal.core.circularLeftInt
import com.appmattus.crypto.internal.core.decodeLEInt
import com.appmattus.crypto.internal.core.encodeLEInt

/**
 * implementation of GOST 28147-89
 */
internal class GOST28147Engine {
    private var workingKey: IntArray? = null
    private var forEncryption = false
    private var S: ByteArray = byteArrayOf(
        0x4, 0xA, 0x9, 0x2, 0xD, 0x8, 0x0, 0xE, 0x6, 0xB, 0x1, 0xC, 0x7, 0xF, 0x5, 0x3,
        0xE, 0xB, 0x4, 0xC, 0x6, 0xD, 0xF, 0xA, 0x2, 0x3, 0x8, 0x1, 0x0, 0x7, 0x5, 0x9,
        0x5, 0x8, 0x1, 0xD, 0xA, 0x3, 0x4, 0x2, 0xE, 0xF, 0xC, 0x7, 0x6, 0x0, 0x9, 0xB,
        0x7, 0xD, 0xA, 0x1, 0x0, 0x8, 0x9, 0xF, 0xE, 0x4, 0x6, 0xC, 0xB, 0x2, 0x5, 0x3,
        0x6, 0xC, 0x7, 0x1, 0x5, 0xF, 0xD, 0x8, 0x4, 0xA, 0x9, 0xE, 0x0, 0x3, 0xB, 0x2,
        0x4, 0xB, 0xA, 0x0, 0x7, 0x2, 0x1, 0xD, 0x3, 0x6, 0x8, 0x5, 0x9, 0xC, 0xF, 0xE,
        0xD, 0xB, 0x4, 0x1, 0x3, 0xF, 0x5, 0x9, 0x0, 0xA, 0xE, 0x7, 0x6, 0x8, 0x2, 0xC,
        0x1, 0xF, 0xD, 0x0, 0x5, 0x7, 0xA, 0x4, 0x9, 0x2, 0x3, 0xE, 0x6, 0xB, 0x8, 0xC
    )

    companion object {
        val blockSize = 8
    }

    /**
     * initialise an GOST28147 cipher.
     *
     * @param forEncryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    fun initWithSbox(
        sBox: ByteArray
    ) {
        //
        // Set the S-Box
        //
        S = sBox.copyOf()
    }

    /**
     * initialise an GOST28147 cipher.
     *
     * @param forEncryption whether or not we are for encryption.
     * @param params the parameters required to set up the cipher.
     * @exception IllegalArgumentException if the params argument is
     * inappropriate.
     */
    fun initWithKey(
        forEncryption: Boolean,
        key: ByteArray
    ) {
        workingKey = generateWorkingKey(
            forEncryption,
            key
        )
    }

    val algorithmName: String
        get() = "GOST28147"

    fun processBlock(
        `in`: ByteArray,
        inOff: Int,
        out: ByteArray,
        outOff: Int
    ): Int {
        if (workingKey == null) {
            throw IllegalStateException("GOST28147 engine not initialised")
        }
        if (inOff + blockSize > `in`.size) {
            throw IllegalStateException("input buffer too short")
        }
        if (outOff + blockSize > out.size) {
            throw IllegalStateException("output buffer too short")
        }
        GOST28147Func(workingKey!!, `in`, inOff, out, outOff)
        return blockSize
    }

    fun reset() {}

    private fun generateWorkingKey(
        forEncryption: Boolean,
        userKey: ByteArray
    ): IntArray {
        this.forEncryption = forEncryption
        if (userKey.size != 32) {
            throw IllegalArgumentException("Key length invalid. Key needs to be 32 byte - 256 bit!!!")
        }
        return IntArray(8) { decodeLEInt(userKey, it * 4) }
    }

    private fun GOST28147_mainStep(n1: Int, key: Int): Int {
        val cm = key + n1 // CM1

        // S-box replacing
        var om: Int = S[0 + (cm shr 0 * 4 and 0xF)].toInt() shl 0 * 4
        om += S[16 + (cm shr 1 * 4 and 0xF)].toInt() shl 1 * 4
        om += S[32 + (cm shr 2 * 4 and 0xF)].toInt() shl 2 * 4
        om += S[48 + (cm shr 3 * 4 and 0xF)].toInt() shl 3 * 4
        om += S[64 + (cm shr 4 * 4 and 0xF)].toInt() shl 4 * 4
        om += S[80 + (cm shr 5 * 4 and 0xF)].toInt() shl 5 * 4
        om += S[96 + (cm shr 6 * 4 and 0xF)].toInt() shl 6 * 4
        om += S[112 + (cm shr 7 * 4 and 0xF)].toInt() shl 7 * 4

        return circularLeftInt(om, 11)
    }

    private fun GOST28147Func(
        workingKey: IntArray,
        `in`: ByteArray,
        inOff: Int,
        out: ByteArray,
        outOff: Int
    ) {
        var N1: Int
        var N2: Int
        var tmp: Int //tmp -> for saving N1
        N1 = decodeLEInt(`in`, inOff)
        N2 = decodeLEInt(`in`, inOff + 4)
        if (forEncryption) {
            for (k in 0 until 3)  // 1-24 steps
            {
                for (j in 0 until 8) {
                    tmp = N1
                    N1 = N2 xor GOST28147_mainStep(N1, workingKey[j]) // CM2
                    N2 = tmp
                }
            }
            for (j in 7 downTo 1)  // 25-31 steps
            {
                tmp = N1
                N1 = N2 xor GOST28147_mainStep(N1, workingKey[j]) // CM2
                N2 = tmp
            }
        } else  //decrypt
        {
            for (j in 0 until 8)  // 1-8 steps
            {
                tmp = N1
                N1 = N2 xor GOST28147_mainStep(N1, workingKey[j]) // CM2
                N2 = tmp
            }
            for (k in 0 until 3)  //9-31 steps
            {
                for (j in 7 downTo 0) {
                    if (k == 2 && j == 0) {
                        break // break 32 step
                    }
                    tmp = N1
                    N1 = N2 xor GOST28147_mainStep(N1, workingKey[j]) // CM2
                    N2 = tmp
                }
            }
        }
        N2 = N2 xor GOST28147_mainStep(N1, workingKey[0]) // 32 step (N1=N1)
        encodeLEInt(N1, out, outOff)
        encodeLEInt(N2, out, outOff + 4)
    }
}
