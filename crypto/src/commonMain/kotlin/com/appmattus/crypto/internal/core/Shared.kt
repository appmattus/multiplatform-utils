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

/**
 * Encode the 32-bit word `val` into the array
 * `buf` at offset `off`, in little-endian
 * convention (least significant byte first).
 *
 * @param `val`   the value to encode
 * @param buf   the destination buffer
 * @param off   the destination offset
 */
internal fun encodeLEInt(`val`: Int, buf: ByteArray, off: Int) {
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
internal fun decodeLEInt(buf: ByteArray, off: Int): Int {
    return (buf[off + 3].toInt() and 0xFF shl 24
            or (buf[off + 2].toInt() and 0xFF shl 16)
            or (buf[off + 1].toInt() and 0xFF shl 8)
            or (buf[off].toInt() and 0xFF))
}

/**
 * Decode a 64-bit little-endian integer.
 *
 * @param buf   the source buffer
 * @param off   the source offset
 * @return  the decoded integer
 */
internal fun decodeLELong(buf: ByteArray, off: Int): Long {
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
internal fun encodeLELong(`val`: Long, dst: ByteArray, off: Int) {
    dst[off + 0] = `val`.toByte()
    dst[off + 1] = (`val`.toInt() ushr 8).toByte()
    dst[off + 2] = (`val`.toInt() ushr 16).toByte()
    dst[off + 3] = (`val`.toInt() ushr 24).toByte()
    dst[off + 4] = (`val` ushr 32).toByte()
    dst[off + 5] = (`val` ushr 40).toByte()
    dst[off + 6] = (`val` ushr 48).toByte()
    dst[off + 7] = (`val` ushr 56).toByte()
}

/**
 * Encode the 32-bit word `val` into the array
 * `buf` at offset `off`, in big-endian
 * convention (most significant byte first).
 *
 * @param val   the value to encode
 * @param buf   the destination buffer
 * @param off   the destination offset
 */
internal fun encodeBEInt(`val`: Int, buf: ByteArray, off: Int) {
    buf[off + 0] = (`val` ushr 24).toByte()
    buf[off + 1] = (`val` ushr 16).toByte()
    buf[off + 2] = (`val` ushr 8).toByte()
    buf[off + 3] = `val`.toByte()
}

/**
 * Decode a 32-bit big-endian word from the array `buf`
 * at offset `off`.
 *
 * @param buf   the source buffer
 * @param off   the source offset
 * @return  the decoded value
 */
internal fun decodeBEInt(buf: ByteArray, off: Int): Int {
    return (buf[off].toInt() and 0xFF shl 24
            or (buf[off + 1].toInt() and 0xFF shl 16)
            or (buf[off + 2].toInt() and 0xFF shl 8)
            or (buf[off + 3].toInt() and 0xFF))
}

/**
 * Encode the 64-bit word `val` into the array
 * `buf` at offset `off`, in big-endian
 * convention (most significant byte first).
 *
 * @param val   the value to encode
 * @param buf   the destination buffer
 * @param off   the destination offset
 */
internal fun encodeBELong(`val`: Long, buf: ByteArray, off: Int) {
    buf[off + 0] = (`val` ushr 56).toByte()
    buf[off + 1] = (`val` ushr 48).toByte()
    buf[off + 2] = (`val` ushr 40).toByte()
    buf[off + 3] = (`val` ushr 32).toByte()
    buf[off + 4] = (`val` ushr 24).toByte()
    buf[off + 5] = (`val` ushr 16).toByte()
    buf[off + 6] = (`val` ushr 8).toByte()
    buf[off + 7] = `val`.toByte()
}

/**
 * Decode a 64-bit big-endian word from the array `buf`
 * at offset `off`.
 *
 * @param buf   the source buffer
 * @param off   the source offset
 * @return  the decoded value
 */
internal fun decodeBELong(buf: ByteArray, off: Int): Long {
    return ((buf[off].toLong() and 0xFF) shl 56
            or ((buf[off + 1].toLong() and 0xFF) shl 48)
            or ((buf[off + 2].toLong() and 0xFF) shl 40)
            or ((buf[off + 3].toLong() and 0xFF) shl 32)
            or ((buf[off + 4].toLong() and 0xFF) shl 24)
            or ((buf[off + 5].toLong() and 0xFF) shl 16)
            or ((buf[off + 6].toLong() and 0xFF) shl 8)
            or (buf[off + 7].toLong() and 0xFF))
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
internal fun circularLeftInt(x: Int, n: Int): Int {
    return x shl n or (x ushr 32 - n)
}

/**
 * Perform a circular rotation by `n` to the right
 * of the 32-bit word `x`. The `n` parameter
 * must lie between 1 and 31 (inclusive).
 *
 * @param x   the value to rotate
 * @param n   the rotation count (between 1 and 31)
 * @return  the rotated value
 */
internal fun circularRightInt(x: Int, n: Int): Int {
    return x ushr n or (x shl 32 - n)
}

/**
 * Perform a circular rotation by `n` to the left
 * of the 64-bit word `x`. The `n` parameter
 * must lie between 1 and 63 (inclusive).
 *
 * @param x   the value to rotate
 * @param n   the rotation count (between 1 and 63)
 * @return  the rotated value
 */
internal fun circularLeftLong(x: Long, n: Int): Long {
    return (x shl n) or (x ushr 64 - n)
}

/**
 * Perform a circular rotation by `n` to the right
 * of the 64-bit word `x`. The `n` parameter
 * must lie between 1 and 63 (inclusive).
 *
 * @param x   the value to rotate
 * @param n   the rotation count (between 1 and 63)
 * @return  the rotated value
 */
internal fun circularRightLong(x: Long, n: Int): Long {
    return x ushr n or (x shl 64 - n)
}
