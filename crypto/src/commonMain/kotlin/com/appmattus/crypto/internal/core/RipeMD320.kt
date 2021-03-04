/*
 * Copyright 2021 Appmattus Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.appmattus.crypto.internal.core

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.internal.core.sphlib.MDHelper

internal class RipeMD320 : MDHelper<RipeMD320>(true, 8) {

    private lateinit var currentVal: IntArray
    private lateinit var x: IntArray

    override fun copy(): RipeMD320 {
        val d = RipeMD320()
        currentVal.copyInto(d.currentVal, 0, 0, currentVal.size)
        return copyState(d)
    }

    override val digestLength: Int
        get() = 40

    override val blockLength: Int
        get() = Algorithm.RipeMD320.blockLength

    override fun engineReset() {
        currentVal[0] = 0x67452301
        currentVal[1] = -0x10325477
        currentVal[2] = -0x67452302
        currentVal[3] = 0x10325476
        currentVal[4] = -0x3c2d1e10
        currentVal[5] = 0x76543210
        currentVal[6] = -0x1234568
        currentVal[7] = -0x76543211
        currentVal[8] = 0x01234567
        currentVal[9] = 0x3c2d1e0f
    }

    override fun doPadding(output: ByteArray, outputOffset: Int) {
        makeMDPadding()
        for (i in 0..9) encodeLEInt(
            currentVal[i],
            output, outputOffset + 4 * i
        )
    }

    override fun doInit() {
        currentVal = IntArray(10)
        x = IntArray(16)
        engineReset()
    }

    @Suppress("JoinDeclarationAndAssignment")
    override fun processBlock(data: ByteArray) {
        run {
            var i = 0
            var j = 0
            while (i < 16) {
                x[i] = decodeLEInt(data, j)
                i++
                j += 4
            }
        }

        var a: Int
        var a2: Int
        var b: Int
        var b2: Int
        var c: Int
        var c2: Int
        var d: Int
        var d2: Int
        var e: Int
        var e2: Int
        var temp: Int
        a = currentVal[0]
        b = currentVal[1]
        c = currentVal[2]
        d = currentVal[3]
        e = currentVal[4]
        a2 = currentVal[5]
        b2 = currentVal[6]
        c2 = currentVal[7]
        d2 = currentVal[8]
        e2 = currentVal[9]
        var j = 0
        while (j < 15) {
            a = circularLeft(a + f1(b, c, d) + x[permute[j]], rotate[j++]) + e
            c = circularLeft(c, 10)
            e = circularLeft(e + f1(a, b, c) + x[permute[j]], rotate[j++]) + d
            b = circularLeft(b, 10)
            d = circularLeft(d + f1(e, a, b) + x[permute[j]], rotate[j++]) + c
            a = circularLeft(a, 10)
            c = circularLeft(c + f1(d, e, a) + x[permute[j]], rotate[j++]) + b
            e = circularLeft(e, 10)
            b = circularLeft(b + f1(c, d, e) + x[permute[j]], rotate[j++]) + a
            d = circularLeft(d, 10)
        }
        a = circularLeft(a + f1(b, c, d) + x[permute[j]], rotate[j++]) + e
        c = circularLeft(c, 10)
        while (j < 31) {
            a2 = circularLeft(
                a2 + f5(
                    b2,
                    c2,
                    d2
                ) + x[permute[j]] + m1, rotate[j++]
            ) + e2
            c2 = circularLeft(c2, 10)
            e2 = circularLeft(
                e2 + f5(
                    a2,
                    b2,
                    c2
                ) + x[permute[j]] + m1, rotate[j++]
            ) + d2
            b2 = circularLeft(b2, 10)
            d2 = circularLeft(
                d2 + f5(
                    e2,
                    a2,
                    b2
                ) + x[permute[j]] + m1, rotate[j++]
            ) + c2
            a2 = circularLeft(a2, 10)
            c2 = circularLeft(
                c2 + f5(
                    d2,
                    e2,
                    a2
                ) + x[permute[j]] + m1, rotate[j++]
            ) + b2
            e2 = circularLeft(e2, 10)
            b2 = circularLeft(
                b2 + f5(
                    c2,
                    d2,
                    e2
                ) + x[permute[j]] + m1, rotate[j++]
            ) + a2
            d2 = circularLeft(d2, 10)
        }
        a2 = circularLeft(a2 + f5(b2, c2, d2) + x[permute[j]] + m1, rotate[j++]) + e2
        c2 = circularLeft(c2, 10)
        temp = a2
        a2 = a
        a = temp
        while (j < 47) {
            e = circularLeft(e + f2(a, b, c) + x[permute[j]] + m2, rotate[j++]) + d
            b = circularLeft(b, 10)
            d = circularLeft(d + f2(e, a, b) + x[permute[j]] + m2, rotate[j++]) + c
            a = circularLeft(a, 10)
            c = circularLeft(c + f2(d, e, a) + x[permute[j]] + m2, rotate[j++]) + b
            e = circularLeft(e, 10)
            b = circularLeft(b + f2(c, d, e) + x[permute[j]] + m2, rotate[j++]) + a
            d = circularLeft(d, 10)
            a = circularLeft(a + f2(b, c, d) + x[permute[j]] + m2, rotate[j++]) + e
            c = circularLeft(c, 10)
        }
        e = circularLeft(e + f2(a, b, c) + x[permute[j]] + m2, rotate[j++]) + d
        b = circularLeft(b, 10)
        while (j < 63) {
            e2 = circularLeft(
                e2 + f4(
                    a2,
                    b2,
                    c2
                ) + x[permute[j]] + m3, rotate[j++]
            ) + d2
            b2 = circularLeft(b2, 10)
            d2 = circularLeft(
                d2 + f4(
                    e2,
                    a2,
                    b2
                ) + x[permute[j]] + m3, rotate[j++]
            ) + c2
            a2 = circularLeft(a2, 10)
            c2 = circularLeft(
                c2 + f4(
                    d2,
                    e2,
                    a2
                ) + x[permute[j]] + m3, rotate[j++]
            ) + b2
            e2 = circularLeft(e2, 10)
            b2 = circularLeft(
                b2 + f4(
                    c2,
                    d2,
                    e2
                ) + x[permute[j]] + m3, rotate[j++]
            ) + a2
            d2 = circularLeft(d2, 10)
            a2 = circularLeft(
                a2 + f4(
                    b2,
                    c2,
                    d2
                ) + x[permute[j]] + m3, rotate[j++]
            ) + e2
            c2 = circularLeft(c2, 10)
        }
        e2 = circularLeft(e2 + f4(a2, b2, c2) + x[permute[j]] + m3, rotate[j++]) + d2
        b2 = circularLeft(b2, 10)
        temp = b2
        b2 = b
        b = temp
        while (j < 79) {
            d = circularLeft(d + f3(e, a, b) + x[permute[j]] + m4, rotate[j++]) + c
            a = circularLeft(a, 10)
            c = circularLeft(c + f3(d, e, a) + x[permute[j]] + m4, rotate[j++]) + b
            e = circularLeft(e, 10)
            b = circularLeft(b + f3(c, d, e) + x[permute[j]] + m4, rotate[j++]) + a
            d = circularLeft(d, 10)
            a = circularLeft(a + f3(b, c, d) + x[permute[j]] + m4, rotate[j++]) + e
            c = circularLeft(c, 10)
            e = circularLeft(e + f3(a, b, c) + x[permute[j]] + m4, rotate[j++]) + d
            b = circularLeft(b, 10)
        }
        d = circularLeft(d + f3(e, a, b) + x[permute[j]] + m4, rotate[j++]) + c
        a = circularLeft(a, 10)
        while (j < 95) {
            d2 = circularLeft(
                d2 + f3(
                    e2,
                    a2,
                    b2
                ) + x[permute[j]] + m5, rotate[j++]
            ) + c2
            a2 = circularLeft(a2, 10)
            c2 = circularLeft(
                c2 + f3(
                    d2,
                    e2,
                    a2
                ) + x[permute[j]] + m5, rotate[j++]
            ) + b2
            e2 = circularLeft(e2, 10)
            b2 = circularLeft(
                b2 + f3(
                    c2,
                    d2,
                    e2
                ) + x[permute[j]] + m5, rotate[j++]
            ) + a2
            d2 = circularLeft(d2, 10)
            a2 = circularLeft(
                a2 + f3(
                    b2,
                    c2,
                    d2
                ) + x[permute[j]] + m5, rotate[j++]
            ) + e2
            c2 = circularLeft(c2, 10)
            e2 = circularLeft(
                e2 + f3(
                    a2,
                    b2,
                    c2
                ) + x[permute[j]] + m5, rotate[j++]
            ) + d2
            b2 = circularLeft(b2, 10)
        }
        d2 = circularLeft(d2 + f3(e2, a2, b2) + x[permute[j]] + m5, rotate[j++]) + c2
        a2 = circularLeft(a2, 10)
        temp = c2
        c2 = c
        c = temp
        while (j < 111) {
            c = circularLeft(c + f4(d, e, a) + x[permute[j]] + m6, rotate[j++]) + b
            e = circularLeft(e, 10)
            b = circularLeft(b + f4(c, d, e) + x[permute[j]] + m6, rotate[j++]) + a
            d = circularLeft(d, 10)
            a = circularLeft(a + f4(b, c, d) + x[permute[j]] + m6, rotate[j++]) + e
            c = circularLeft(c, 10)
            e = circularLeft(e + f4(a, b, c) + x[permute[j]] + m6, rotate[j++]) + d
            b = circularLeft(b, 10)
            d = circularLeft(d + f4(e, a, b) + x[permute[j]] + m6, rotate[j++]) + c
            a = circularLeft(a, 10)
        }
        c = circularLeft(c + f4(d, e, a) + x[permute[j]] + m6, rotate[j++]) + b
        e = circularLeft(e, 10)
        while (j < 127) {
            c2 = circularLeft(
                c2 + f2(
                    d2,
                    e2,
                    a2
                ) + x[permute[j]] + m7, rotate[j++]
            ) + b2
            e2 = circularLeft(e2, 10)
            b2 = circularLeft(
                b2 + f2(
                    c2,
                    d2,
                    e2
                ) + x[permute[j]] + m7, rotate[j++]
            ) + a2
            d2 = circularLeft(d2, 10)
            a2 = circularLeft(
                a2 + f2(
                    b2,
                    c2,
                    d2
                ) + x[permute[j]] + m7, rotate[j++]
            ) + e2
            c2 = circularLeft(c2, 10)
            e2 = circularLeft(
                e2 + f2(
                    a2,
                    b2,
                    c2
                ) + x[permute[j]] + m7, rotate[j++]
            ) + d2
            b2 = circularLeft(b2, 10)
            d2 = circularLeft(
                d2 + f2(
                    e2,
                    a2,
                    b2
                ) + x[permute[j]] + m7, rotate[j++]
            ) + c2
            a2 = circularLeft(a2, 10)
        }
        c2 = circularLeft(c2 + f2(d2, e2, a2) + x[permute[j]] + m7, rotate[j++]) + b2
        e2 = circularLeft(e2, 10)
        temp = d2
        d2 = d
        d = temp
        while (j < 143) {
            b = circularLeft(b + f5(c, d, e) + x[permute[j]] + m8, rotate[j++]) + a
            d = circularLeft(d, 10)
            a = circularLeft(a + f5(b, c, d) + x[permute[j]] + m8, rotate[j++]) + e
            c = circularLeft(c, 10)
            e = circularLeft(e + f5(a, b, c) + x[permute[j]] + m8, rotate[j++]) + d
            b = circularLeft(b, 10)
            d = circularLeft(d + f5(e, a, b) + x[permute[j]] + m8, rotate[j++]) + c
            a = circularLeft(a, 10)
            c = circularLeft(c + f5(d, e, a) + x[permute[j]] + m8, rotate[j++]) + b
            e = circularLeft(e, 10)
        }
        b = circularLeft(b + f5(c, d, e) + x[permute[j]] + m8, rotate[j++]) + a
        d = circularLeft(d, 10)
        while (j < 159) {
            b2 = circularLeft(b2 + f1(c2, d2, e2) + x[permute[j]], rotate[j++]) + a2
            d2 = circularLeft(d2, 10)
            a2 = circularLeft(a2 + f1(b2, c2, d2) + x[permute[j]], rotate[j++]) + e2
            c2 = circularLeft(c2, 10)
            e2 = circularLeft(e2 + f1(a2, b2, c2) + x[permute[j]], rotate[j++]) + d2
            b2 = circularLeft(b2, 10)
            d2 = circularLeft(d2 + f1(e2, a2, b2) + x[permute[j]], rotate[j++]) + c2
            a2 = circularLeft(a2, 10)
            c2 = circularLeft(c2 + f1(d2, e2, a2) + x[permute[j]], rotate[j++]) + b2
            e2 = circularLeft(e2, 10)
        }
        b2 = circularLeft(b2 + f1(c2, d2, e2) + x[permute[j]], rotate[j]) + a2
        d2 = circularLeft(d2, 10)
        currentVal[0] += a
        currentVal[1] += b
        currentVal[2] += c
        currentVal[3] += d
        currentVal[4] += e2
        currentVal[5] += a2
        currentVal[6] += b2
        currentVal[7] += c2
        currentVal[8] += d2
        currentVal[9] += e
    }

    override fun toString() = Algorithm.RipeMD320.algorithmName

    companion object {

        private val permute = intArrayOf(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
            7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
            6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
            3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
            15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
            1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
            8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
            4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
            12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
        )
        private val rotate = intArrayOf(
            11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
            8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
            7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
            9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
            11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
            9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
            11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
            15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
            9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
            8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
        )
        private const val m1 = 0x50a28be6
        private const val m2 = 0x5a827999
        private const val m3 = 0x5c4dd124
        private const val m4 = 0x6ed9eba1
        private const val m5 = 0x6d703ef3
        private const val m6 = -0x70e44324
        private const val m7 = 0x7a6d76e9
        private const val m8 = -0x56ac02b2

        private fun f1(a: Int, b: Int, c: Int): Int {
            return a xor b xor c
        }

        private fun f2(a: Int, b: Int, c: Int): Int {
            return a and b or (a.inv() and c)
        }

        private fun f3(a: Int, b: Int, c: Int): Int {
            return a or b.inv() xor c
        }

        private fun f4(a: Int, b: Int, c: Int): Int {
            return a and c or (b and c.inv())
        }

        private fun f5(a: Int, b: Int, c: Int): Int {
            return a xor (b or c.inv())
        }

        /**
         * Perform a circular rotation by `n` to the left
         * of the 32-bit word `x`. The `n` parameter
         * must lie between 1 and 31 (inclusive).
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
