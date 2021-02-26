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
 * This class implements the padding common to MD4, MD5, the SHA family,
 * and RIPEMD-160. This code works as long as the internal block length
 * is a power of 2, which is the case for all these algorithms.
 *
 * @version   $Revision: 157 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 *
 * Little-endian padding is for MD4, MD5 and
 * RIPEMD-160; the SHA family uses big-endian padding. The
 * MD padding includes an encoding of the input message bit length,
 * which is over 64 bits for some algorithms, 128-bit for others
 * (namely SHA-384 and SHA-512). Note that this implementation
 * handles only message lengths which fit on 64 bits. The first
 * additional byte value is specified; this is normally 0x80,
 * except for Tiger (not Tiger2) which uses 0x01.
 *
 * @param littleEndian   `true` for little-endian padding
 * @param lenlen         the length encoding length, in bytes (must
 * be at least 8)
 * @param fbyte          the first padding byte
 */
abstract class MDHelper<D : MDHelper<D>>(
    private val littleEndian: Boolean,
    lenlen: Int,
    private val fbyte: Byte = 0x80.toByte()
) : DigestEngine<D>() {

    private val countBuf: ByteArray = ByteArray(lenlen)

    /**
     * Compute the padding. The padding data is input into the engine,
     * which is flushed.
     */
    protected fun makeMDPadding() {
        val dataLen = flush()
        val blen = blockLength
        var currentLength = blockCount * blen.toLong()
        currentLength = (currentLength + dataLen.toLong()) * 8L
        val lenlen = countBuf.size
        if (littleEndian) {
            encodeLEInt(currentLength.toInt(), countBuf, 0)
            encodeLEInt((currentLength ushr 32).toInt(), countBuf, 4)
        } else {
            encodeBEInt(
                (currentLength ushr 32).toInt(),
                countBuf, lenlen - 8
            )
            encodeBEInt(
                currentLength.toInt(),
                countBuf, lenlen - 4
            )
        }
        val endLen = dataLen + lenlen + blen and (blen - 1).inv()
        update(fbyte)
        for (i in dataLen + 1 until endLen - lenlen) update(0.toByte())
        update(countBuf)

        /*
		 * This code is used only for debugging purposes.
		 *
		if (flush() != 0)
			throw new Error("panic: buffering went astray");
		 *
		 */
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
         * Encode the 32-bit word `val` into the array
         * `buf` at offset `off`, in big-endian
         * convention (most significant byte first).
         *
         * @param val   the value to encode
         * @param buf   the destination buffer
         * @param off   the destination offset
         */
        private fun encodeBEInt(`val`: Int, buf: ByteArray, off: Int) {
            buf[off + 0] = (`val` ushr 24).toByte()
            buf[off + 1] = (`val` ushr 16).toByte()
            buf[off + 2] = (`val` ushr 8).toByte()
            buf[off + 3] = `val`.toByte()
        }
    }
}
