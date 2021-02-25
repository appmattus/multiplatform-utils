// $Id: SHA2BigCore.java 214 2010-06-03 17:25:08Z tp $
package fr.cryptohash

/**
 * This class implements SHA-384 and SHA-512, which differ only by the IV
 * and the output length.
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
 * @version   $Revision: 214 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
abstract class SHA2BigCore : MDHelper(false, 16) {
    /**
     * Create the object.
     */

    private lateinit var currentVal: LongArray
    private lateinit var W: LongArray

    /** @see DigestEngine
     */
    protected fun copyState(dst: SHA2BigCore): Digest {
        currentVal.copyInto(dst.currentVal, 0, 0, currentVal.size)
        return super.copyState(dst)
    }

    /** @see Digest
     */
    override val blockLength: Int
        get() = 128

    /** @see DigestEngine
     */
    override fun engineReset() {
        initVal.copyInto(currentVal, 0, 0, 8)
    }

    /**
     * Get the initial value for this algorithm.
     *
     * @return  the initial value (eight 64-bit words)
     */
    abstract val initVal: LongArray

    /** @see DigestEngine
     */
    override fun doPadding(output: ByteArray, outputOffset: Int) {
        makeMDPadding()
        val olen = digestLength
        var i = 0
        var j = 0
        while (j < olen) {
            encodeBELong(currentVal[i], output, outputOffset + j)
            i++
            j += 8
        }
    }

    /** @see DigestEngine
     */
    override fun doInit() {
        currentVal = LongArray(8)
        W = LongArray(80)
        engineReset()
    }

    /** @see DigestEngine
     */
    override fun processBlock(data: ByteArray) {
        var A = currentVal[0]
        var B = currentVal[1]
        var C = currentVal[2]
        var D = currentVal[3]
        var E = currentVal[4]
        var F = currentVal[5]
        var G = currentVal[6]
        var H = currentVal[7]
        for (i in 0..15) W[i] = decodeBELong(data, 8 * i)
        for (i in 16..79) {
            W[i] = ((circularLeft(W[i - 2], 45)
                    xor circularLeft(W[i - 2], 3)
                    xor (W[i - 2] ushr 6))
                    + W[i - 7]
                    + (circularLeft(W[i - 15], 63)
                    xor circularLeft(W[i - 15], 56)
                    xor (W[i - 15] ushr 7))
                    + W[i - 16])
        }
        for (i in 0..79) {
            /*
			 * Microsoft JVM (old JVM with IE 5.5) has trouble
			 * with complex expressions involving the "long"
			 * type. Hence, we split these expressions into
			 * simpler elementary expressions. Such a split
			 * should not harm recent JDK optimizers.
			 */
            var T1 = circularLeft(E, 50)
            T1 = T1 xor circularLeft(E, 46)
            T1 = T1 xor circularLeft(E, 23)
            T1 += H
            T1 += F and E xor (G and E.inv())
            T1 += K[i]
            T1 += W[i]
            var T2 = circularLeft(A, 36)
            T2 = T2 xor circularLeft(A, 30)
            T2 = T2 xor circularLeft(A, 25)
            T2 += A and B xor (A and C) xor (B and C)
            H = G
            G = F
            F = E
            E = D + T1
            D = C
            C = B
            B = A
            A = T1 + T2
        }
        currentVal[0] += A
        currentVal[1] += B
        currentVal[2] += C
        currentVal[3] += D
        currentVal[4] += E
        currentVal[5] += F
        currentVal[6] += G
        currentVal[7] += H
    }

    /** @see Digest
     */
    override fun toString(): String {
        return "SHA-" + (digestLength shl 3)
    }

    companion object {
        /** private special values.  */
        private val K = longArrayOf(
            0x428A2F98D728AE22L, 0x7137449123EF65CDL, -0x4a3f043013b2c4d1L,
            -0x164a245a7e762444L, 0x3956C25BF348B538L, 0x59F111F1B605D019L,
            -0x6dc07d5b50e6b065L, -0x54e3a12a25927ee8L, -0x27f855675cfcfdbeL,
            0x12835B0145706FBEL, 0x243185BE4EE4B28CL, 0x550C7DC3D5FFB4E2L,
            0x72BE5D74F27B896FL, -0x7f214e01c4e9694fL, -0x6423f958da38edcbL,
            -0x3e640e8b3096d96cL, -0x1b64963e610eb52eL, -0x1041b879c7b0da1dL,
            0x0FC19DC68B8CD5B5L, 0x240CA1CC77AC9C65L, 0x2DE92C6F592B0275L,
            0x4A7484AA6EA6E483L, 0x5CB0A9DCBD41FBD4L, 0x76F988DA831153B5L,
            -0x67c1aead11992055L, -0x57ce3992d24bcdf0L, -0x4ffcd8376704dec1L,
            -0x40a680384110f11cL, -0x391ff40cc257703eL, -0x2a586eb86cf558dbL,
            0x06CA6351E003826FL, 0x142929670A0E6E70L, 0x27B70A8546D22FFCL,
            0x2E1B21385C26C926L, 0x4D2C6DFC5AC42AEDL, 0x53380D139D95B3DFL,
            0x650A73548BAF63DEL, 0x766A0ABB3C77B2A8L, -0x7e3d36d1b812511aL,
            -0x6d8dd37aeb7dcac5L, -0x5d40175eb30efc9cL, -0x57e599b443bdcfffL,
            -0x3db4748f2f07686fL, -0x3893ae5cf9ab41d0L, -0x2e6d17e62910ade8L,
            -0x2966f9dbaa9a56f0L, -0xbf1ca7aa88edfd6L, 0x106AA07032BBD1B8L,
            0x19A4C116B8D2D0C8L, 0x1E376C085141AB53L, 0x2748774CDF8EEB99L,
            0x34B0BCB5E19B48A8L, 0x391C0CB3C5C95A63L, 0x4ED8AA4AE3418ACBL,
            0x5B9CCA4F7763E373L, 0x682E6FF3D6B2B8A3L, 0x748F82EE5DEFB2FCL,
            0x78A5636F43172F60L, -0x7b3787eb5e0f548eL, -0x7338fdf7e59bc614L,
            -0x6f410005dc9ce1d8L, -0x5baf9314217d4217L, -0x41065c084d3986ebL,
            -0x398e870d1c8dacd5L, -0x35d8c13115d99e64L, -0x2e794738de3f3df9L,
            -0x15258229321f14e2L, -0xa82b08011912e88L, 0x06F067AA72176FBAL,
            0x0A637DC5A2C898A6L, 0x113F9804BEF90DAEL, 0x1B710B35131C471BL,
            0x28DB77F523047D84L, 0x32CAAB7B40C72493L, 0x3C9EBE0A15C9BEBCL,
            0x431D67C49C100D4CL, 0x4CC5D4BECB3E42B6L, 0x597F299CFC657E2AL,
            0x5FCB6FAB3AD6FAECL, 0x6C44198C4A475817L
        )

        /**
         * Encode the 64-bit word `val` into the array
         * `buf` at offset `off`, in big-endian
         * convention (most significant byte first).
         *
         * @param val   the value to encode
         * @param buf   the destination buffer
         * @param off   the destination offset
         */
        private fun encodeBELong(`val`: Long, buf: ByteArray, off: Int) {
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
        private fun decodeBELong(buf: ByteArray, off: Int): Long {
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
         * of the 64-bit word `x`. The `n` parameter
         * must lie between 1 and 63 (inclusive).
         *
         * @param x   the value to rotate
         * @param n   the rotation count (between 1 and 63)
         * @return  the rotated value
         */
        private fun circularLeft(x: Long, n: Int): Long {
            return x shl n or (x ushr 64 - n)
        }
    }
}
