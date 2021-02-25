// $Id: SHA0.java 214 2010-06-03 17:25:08Z tp $
package fr.cryptohash

/**
 *
 * This class implements the SHA-0 digest algorithm under the [ ] API. SHA-0 was defined by FIPS 180 (the original standard,
 * now obsolete).
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
class SHA0
/**
 * Build the object.
 */
    : MDHelper(false, 8) {
    private lateinit var currentVal: IntArray

    /** @see Digest
     */
    override fun copy(): Digest {
        val d = SHA0()
        currentVal.copyInto(d.currentVal, 0, 0, currentVal.size)
        return copyState(d)
    }

    /** @see Digest
     */
    override val digestLength: Int
        get() = 20

    /** @see Digest
     */
    override val blockLength: Int
        get() = 64

    /** @see DigestEngine
     */
    override fun engineReset() {
        currentVal[0] = 0x67452301
        currentVal[1] = -0x10325477
        currentVal[2] = -0x67452302
        currentVal[3] = 0x10325476
        currentVal[4] = -0x3c2d1e10
    }

    /** @see DigestEngine
     */
    override fun doPadding(output: ByteArray, outputOffset: Int) {
        makeMDPadding()
        for (i in 0..4) encodeBEInt(
            currentVal[i],
            output, outputOffset + 4 * i
        )
    }

    /** @see DigestEngine
     */
    override fun doInit() {
        currentVal = IntArray(5)
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
        var W0 = decodeBEInt(data, 0)
        E = ((A shl 5 or (A ushr 27)) + (B and C or (B.inv() and D))
                + E + W0 + 0x5A827999)
        B = B shl 30 or (B ushr 2)
        var W1 = decodeBEInt(data, 4)
        D = ((E shl 5 or (E ushr 27)) + (A and B or (A.inv() and C))
                + D + W1 + 0x5A827999)
        A = A shl 30 or (A ushr 2)
        var W2 = decodeBEInt(data, 8)
        C = ((D shl 5 or (D ushr 27)) + (E and A or (E.inv() and B))
                + C + W2 + 0x5A827999)
        E = E shl 30 or (E ushr 2)
        var W3 = decodeBEInt(data, 12)
        B = ((C shl 5 or (C ushr 27)) + (D and E or (D.inv() and A))
                + B + W3 + 0x5A827999)
        D = D shl 30 or (D ushr 2)
        var W4 = decodeBEInt(data, 16)
        A = ((B shl 5 or (B ushr 27)) + (C and D or (C.inv() and E))
                + A + W4 + 0x5A827999)
        C = C shl 30 or (C ushr 2)
        var W5 = decodeBEInt(data, 20)
        E = ((A shl 5 or (A ushr 27)) + (B and C or (B.inv() and D))
                + E + W5 + 0x5A827999)
        B = B shl 30 or (B ushr 2)
        var W6 = decodeBEInt(data, 24)
        D = ((E shl 5 or (E ushr 27)) + (A and B or (A.inv() and C))
                + D + W6 + 0x5A827999)
        A = A shl 30 or (A ushr 2)
        var W7 = decodeBEInt(data, 28)
        C = ((D shl 5 or (D ushr 27)) + (E and A or (E.inv() and B))
                + C + W7 + 0x5A827999)
        E = E shl 30 or (E ushr 2)
        var W8 = decodeBEInt(data, 32)
        B = ((C shl 5 or (C ushr 27)) + (D and E or (D.inv() and A))
                + B + W8 + 0x5A827999)
        D = D shl 30 or (D ushr 2)
        var W9 = decodeBEInt(data, 36)
        A = ((B shl 5 or (B ushr 27)) + (C and D or (C.inv() and E))
                + A + W9 + 0x5A827999)
        C = C shl 30 or (C ushr 2)
        var Wa = decodeBEInt(data, 40)
        E = ((A shl 5 or (A ushr 27)) + (B and C or (B.inv() and D))
                + E + Wa + 0x5A827999)
        B = B shl 30 or (B ushr 2)
        var Wb = decodeBEInt(data, 44)
        D = ((E shl 5 or (E ushr 27)) + (A and B or (A.inv() and C))
                + D + Wb + 0x5A827999)
        A = A shl 30 or (A ushr 2)
        var Wc = decodeBEInt(data, 48)
        C = ((D shl 5 or (D ushr 27)) + (E and A or (E.inv() and B))
                + C + Wc + 0x5A827999)
        E = E shl 30 or (E ushr 2)
        var Wd = decodeBEInt(data, 52)
        B = ((C shl 5 or (C ushr 27)) + (D and E or (D.inv() and A))
                + B + Wd + 0x5A827999)
        D = D shl 30 or (D ushr 2)
        var We = decodeBEInt(data, 56)
        A = ((B shl 5 or (B ushr 27)) + (C and D or (C.inv() and E))
                + A + We + 0x5A827999)
        C = C shl 30 or (C ushr 2)
        var Wf = decodeBEInt(data, 60)
        E = ((A shl 5 or (A ushr 27)) + (B and C or (B.inv() and D))
                + E + Wf + 0x5A827999)
        B = B shl 30 or (B ushr 2)
        W0 = Wd xor W8 xor W2 xor W0
        D = ((E shl 5 or (E ushr 27)) + (A and B or (A.inv() and C))
                + D + W0 + 0x5A827999)
        A = A shl 30 or (A ushr 2)
        W1 = We xor W9 xor W3 xor W1
        C = ((D shl 5 or (D ushr 27)) + (E and A or (E.inv() and B))
                + C + W1 + 0x5A827999)
        E = E shl 30 or (E ushr 2)
        W2 = Wf xor Wa xor W4 xor W2
        B = ((C shl 5 or (C ushr 27)) + (D and E or (D.inv() and A))
                + B + W2 + 0x5A827999)
        D = D shl 30 or (D ushr 2)
        W3 = W0 xor Wb xor W5 xor W3
        A = ((B shl 5 or (B ushr 27)) + (C and D or (C.inv() and E))
                + A + W3 + 0x5A827999)
        C = C shl 30 or (C ushr 2)
        W4 = W1 xor Wc xor W6 xor W4
        E = ((A shl 5 or (A ushr 27)) + (B xor C xor D)
                + E + W4 + 0x6ED9EBA1)
        B = B shl 30 or (B ushr 2)
        W5 = W2 xor Wd xor W7 xor W5
        D = ((E shl 5 or (E ushr 27)) + (A xor B xor C)
                + D + W5 + 0x6ED9EBA1)
        A = A shl 30 or (A ushr 2)
        W6 = W3 xor We xor W8 xor W6
        C = ((D shl 5 or (D ushr 27)) + (E xor A xor B)
                + C + W6 + 0x6ED9EBA1)
        E = E shl 30 or (E ushr 2)
        W7 = W4 xor Wf xor W9 xor W7
        B = ((C shl 5 or (C ushr 27)) + (D xor E xor A)
                + B + W7 + 0x6ED9EBA1)
        D = D shl 30 or (D ushr 2)
        W8 = W5 xor W0 xor Wa xor W8
        A = ((B shl 5 or (B ushr 27)) + (C xor D xor E)
                + A + W8 + 0x6ED9EBA1)
        C = C shl 30 or (C ushr 2)
        W9 = W6 xor W1 xor Wb xor W9
        E = ((A shl 5 or (A ushr 27)) + (B xor C xor D)
                + E + W9 + 0x6ED9EBA1)
        B = B shl 30 or (B ushr 2)
        Wa = W7 xor W2 xor Wc xor Wa
        D = ((E shl 5 or (E ushr 27)) + (A xor B xor C)
                + D + Wa + 0x6ED9EBA1)
        A = A shl 30 or (A ushr 2)
        Wb = W8 xor W3 xor Wd xor Wb
        C = ((D shl 5 or (D ushr 27)) + (E xor A xor B)
                + C + Wb + 0x6ED9EBA1)
        E = E shl 30 or (E ushr 2)
        Wc = W9 xor W4 xor We xor Wc
        B = ((C shl 5 or (C ushr 27)) + (D xor E xor A)
                + B + Wc + 0x6ED9EBA1)
        D = D shl 30 or (D ushr 2)
        Wd = Wa xor W5 xor Wf xor Wd
        A = ((B shl 5 or (B ushr 27)) + (C xor D xor E)
                + A + Wd + 0x6ED9EBA1)
        C = C shl 30 or (C ushr 2)
        We = Wb xor W6 xor W0 xor We
        E = ((A shl 5 or (A ushr 27)) + (B xor C xor D)
                + E + We + 0x6ED9EBA1)
        B = B shl 30 or (B ushr 2)
        Wf = Wc xor W7 xor W1 xor Wf
        D = ((E shl 5 or (E ushr 27)) + (A xor B xor C)
                + D + Wf + 0x6ED9EBA1)
        A = A shl 30 or (A ushr 2)
        W0 = Wd xor W8 xor W2 xor W0
        C = ((D shl 5 or (D ushr 27)) + (E xor A xor B)
                + C + W0 + 0x6ED9EBA1)
        E = E shl 30 or (E ushr 2)
        W1 = We xor W9 xor W3 xor W1
        B = ((C shl 5 or (C ushr 27)) + (D xor E xor A)
                + B + W1 + 0x6ED9EBA1)
        D = D shl 30 or (D ushr 2)
        W2 = Wf xor Wa xor W4 xor W2
        A = ((B shl 5 or (B ushr 27)) + (C xor D xor E)
                + A + W2 + 0x6ED9EBA1)
        C = C shl 30 or (C ushr 2)
        W3 = W0 xor Wb xor W5 xor W3
        E = ((A shl 5 or (A ushr 27)) + (B xor C xor D)
                + E + W3 + 0x6ED9EBA1)
        B = B shl 30 or (B ushr 2)
        W4 = W1 xor Wc xor W6 xor W4
        D = ((E shl 5 or (E ushr 27)) + (A xor B xor C)
                + D + W4 + 0x6ED9EBA1)
        A = A shl 30 or (A ushr 2)
        W5 = W2 xor Wd xor W7 xor W5
        C = ((D shl 5 or (D ushr 27)) + (E xor A xor B)
                + C + W5 + 0x6ED9EBA1)
        E = E shl 30 or (E ushr 2)
        W6 = W3 xor We xor W8 xor W6
        B = ((C shl 5 or (C ushr 27)) + (D xor E xor A)
                + B + W6 + 0x6ED9EBA1)
        D = D shl 30 or (D ushr 2)
        W7 = W4 xor Wf xor W9 xor W7
        A = ((B shl 5 or (B ushr 27)) + (C xor D xor E)
                + A + W7 + 0x6ED9EBA1)
        C = C shl 30 or (C ushr 2)
        W8 = W5 xor W0 xor Wa xor W8
        E = ((A shl 5 or (A ushr 27)) + (B and C or (B and D) or (C and D))
                + E + W8 + -0x70e44324)
        B = B shl 30 or (B ushr 2)
        W9 = W6 xor W1 xor Wb xor W9
        D = ((E shl 5 or (E ushr 27)) + (A and B or (A and C) or (B and C))
                + D + W9 + -0x70e44324)
        A = A shl 30 or (A ushr 2)
        Wa = W7 xor W2 xor Wc xor Wa
        C = ((D shl 5 or (D ushr 27)) + (E and A or (E and B) or (A and B))
                + C + Wa + -0x70e44324)
        E = E shl 30 or (E ushr 2)
        Wb = W8 xor W3 xor Wd xor Wb
        B = ((C shl 5 or (C ushr 27)) + (D and E or (D and A) or (E and A))
                + B + Wb + -0x70e44324)
        D = D shl 30 or (D ushr 2)
        Wc = W9 xor W4 xor We xor Wc
        A = ((B shl 5 or (B ushr 27)) + (C and D or (C and E) or (D and E))
                + A + Wc + -0x70e44324)
        C = C shl 30 or (C ushr 2)
        Wd = Wa xor W5 xor Wf xor Wd
        E = ((A shl 5 or (A ushr 27)) + (B and C or (B and D) or (C and D))
                + E + Wd + -0x70e44324)
        B = B shl 30 or (B ushr 2)
        We = Wb xor W6 xor W0 xor We
        D = ((E shl 5 or (E ushr 27)) + (A and B or (A and C) or (B and C))
                + D + We + -0x70e44324)
        A = A shl 30 or (A ushr 2)
        Wf = Wc xor W7 xor W1 xor Wf
        C = ((D shl 5 or (D ushr 27)) + (E and A or (E and B) or (A and B))
                + C + Wf + -0x70e44324)
        E = E shl 30 or (E ushr 2)
        W0 = Wd xor W8 xor W2 xor W0
        B = ((C shl 5 or (C ushr 27)) + (D and E or (D and A) or (E and A))
                + B + W0 + -0x70e44324)
        D = D shl 30 or (D ushr 2)
        W1 = We xor W9 xor W3 xor W1
        A = ((B shl 5 or (B ushr 27)) + (C and D or (C and E) or (D and E))
                + A + W1 + -0x70e44324)
        C = C shl 30 or (C ushr 2)
        W2 = Wf xor Wa xor W4 xor W2
        E = ((A shl 5 or (A ushr 27)) + (B and C or (B and D) or (C and D))
                + E + W2 + -0x70e44324)
        B = B shl 30 or (B ushr 2)
        W3 = W0 xor Wb xor W5 xor W3
        D = ((E shl 5 or (E ushr 27)) + (A and B or (A and C) or (B and C))
                + D + W3 + -0x70e44324)
        A = A shl 30 or (A ushr 2)
        W4 = W1 xor Wc xor W6 xor W4
        C = ((D shl 5 or (D ushr 27)) + (E and A or (E and B) or (A and B))
                + C + W4 + -0x70e44324)
        E = E shl 30 or (E ushr 2)
        W5 = W2 xor Wd xor W7 xor W5
        B = ((C shl 5 or (C ushr 27)) + (D and E or (D and A) or (E and A))
                + B + W5 + -0x70e44324)
        D = D shl 30 or (D ushr 2)
        W6 = W3 xor We xor W8 xor W6
        A = ((B shl 5 or (B ushr 27)) + (C and D or (C and E) or (D and E))
                + A + W6 + -0x70e44324)
        C = C shl 30 or (C ushr 2)
        W7 = W4 xor Wf xor W9 xor W7
        E = ((A shl 5 or (A ushr 27)) + (B and C or (B and D) or (C and D))
                + E + W7 + -0x70e44324)
        B = B shl 30 or (B ushr 2)
        W8 = W5 xor W0 xor Wa xor W8
        D = ((E shl 5 or (E ushr 27)) + (A and B or (A and C) or (B and C))
                + D + W8 + -0x70e44324)
        A = A shl 30 or (A ushr 2)
        W9 = W6 xor W1 xor Wb xor W9
        C = ((D shl 5 or (D ushr 27)) + (E and A or (E and B) or (A and B))
                + C + W9 + -0x70e44324)
        E = E shl 30 or (E ushr 2)
        Wa = W7 xor W2 xor Wc xor Wa
        B = ((C shl 5 or (C ushr 27)) + (D and E or (D and A) or (E and A))
                + B + Wa + -0x70e44324)
        D = D shl 30 or (D ushr 2)
        Wb = W8 xor W3 xor Wd xor Wb
        A = ((B shl 5 or (B ushr 27)) + (C and D or (C and E) or (D and E))
                + A + Wb + -0x70e44324)
        C = C shl 30 or (C ushr 2)
        Wc = W9 xor W4 xor We xor Wc
        E = ((A shl 5 or (A ushr 27)) + (B xor C xor D)
                + E + Wc + -0x359d3e2a)
        B = B shl 30 or (B ushr 2)
        Wd = Wa xor W5 xor Wf xor Wd
        D = ((E shl 5 or (E ushr 27)) + (A xor B xor C)
                + D + Wd + -0x359d3e2a)
        A = A shl 30 or (A ushr 2)
        We = Wb xor W6 xor W0 xor We
        C = ((D shl 5 or (D ushr 27)) + (E xor A xor B)
                + C + We + -0x359d3e2a)
        E = E shl 30 or (E ushr 2)
        Wf = Wc xor W7 xor W1 xor Wf
        B = ((C shl 5 or (C ushr 27)) + (D xor E xor A)
                + B + Wf + -0x359d3e2a)
        D = D shl 30 or (D ushr 2)
        W0 = Wd xor W8 xor W2 xor W0
        A = ((B shl 5 or (B ushr 27)) + (C xor D xor E)
                + A + W0 + -0x359d3e2a)
        C = C shl 30 or (C ushr 2)
        W1 = We xor W9 xor W3 xor W1
        E = ((A shl 5 or (A ushr 27)) + (B xor C xor D)
                + E + W1 + -0x359d3e2a)
        B = B shl 30 or (B ushr 2)
        W2 = Wf xor Wa xor W4 xor W2
        D = ((E shl 5 or (E ushr 27)) + (A xor B xor C)
                + D + W2 + -0x359d3e2a)
        A = A shl 30 or (A ushr 2)
        W3 = W0 xor Wb xor W5 xor W3
        C = ((D shl 5 or (D ushr 27)) + (E xor A xor B)
                + C + W3 + -0x359d3e2a)
        E = E shl 30 or (E ushr 2)
        W4 = W1 xor Wc xor W6 xor W4
        B = ((C shl 5 or (C ushr 27)) + (D xor E xor A)
                + B + W4 + -0x359d3e2a)
        D = D shl 30 or (D ushr 2)
        W5 = W2 xor Wd xor W7 xor W5
        A = ((B shl 5 or (B ushr 27)) + (C xor D xor E)
                + A + W5 + -0x359d3e2a)
        C = C shl 30 or (C ushr 2)
        W6 = W3 xor We xor W8 xor W6
        E = ((A shl 5 or (A ushr 27)) + (B xor C xor D)
                + E + W6 + -0x359d3e2a)
        B = B shl 30 or (B ushr 2)
        W7 = W4 xor Wf xor W9 xor W7
        D = ((E shl 5 or (E ushr 27)) + (A xor B xor C)
                + D + W7 + -0x359d3e2a)
        A = A shl 30 or (A ushr 2)
        W8 = W5 xor W0 xor Wa xor W8
        C = ((D shl 5 or (D ushr 27)) + (E xor A xor B)
                + C + W8 + -0x359d3e2a)
        E = E shl 30 or (E ushr 2)
        W9 = W6 xor W1 xor Wb xor W9
        B = ((C shl 5 or (C ushr 27)) + (D xor E xor A)
                + B + W9 + -0x359d3e2a)
        D = D shl 30 or (D ushr 2)
        Wa = W7 xor W2 xor Wc xor Wa
        A = ((B shl 5 or (B ushr 27)) + (C xor D xor E)
                + A + Wa + -0x359d3e2a)
        C = C shl 30 or (C ushr 2)
        Wb = W8 xor W3 xor Wd xor Wb
        E = ((A shl 5 or (A ushr 27)) + (B xor C xor D)
                + E + Wb + -0x359d3e2a)
        B = B shl 30 or (B ushr 2)
        Wc = W9 xor W4 xor We xor Wc
        D = ((E shl 5 or (E ushr 27)) + (A xor B xor C)
                + D + Wc + -0x359d3e2a)
        A = A shl 30 or (A ushr 2)
        Wd = Wa xor W5 xor Wf xor Wd
        C = ((D shl 5 or (D ushr 27)) + (E xor A xor B)
                + C + Wd + -0x359d3e2a)
        E = E shl 30 or (E ushr 2)
        We = Wb xor W6 xor W0 xor We
        B = ((C shl 5 or (C ushr 27)) + (D xor E xor A)
                + B + We + -0x359d3e2a)
        D = D shl 30 or (D ushr 2)
        Wf = Wc xor W7 xor W1 xor Wf
        A = ((B shl 5 or (B ushr 27)) + (C xor D xor E)
                + A + Wf + -0x359d3e2a)
        C = C shl 30 or (C ushr 2)
        currentVal[0] += A
        currentVal[1] += B
        currentVal[2] += C
        currentVal[3] += D
        currentVal[4] += E
    }

    /** @see Digest
     */
    override fun toString(): String {
        return "SHA-0"
    }

    companion object {
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

        /**
         * Decode a 32-bit big-endian word from the array `buf`
         * at offset `off`.
         *
         * @param buf   the source buffer
         * @param off   the source offset
         * @return  the decoded value
         */
        private fun decodeBEInt(buf: ByteArray, off: Int): Int {
            return (buf[off].toInt() and 0xFF shl 24
                    or (buf[off + 1].toInt() and 0xFF shl 16)
                    or (buf[off + 2].toInt() and 0xFF shl 8)
                    or (buf[off + 3].toInt() and 0xFF))
        }
    }
}
