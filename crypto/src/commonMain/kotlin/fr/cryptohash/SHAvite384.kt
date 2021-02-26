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
 * This class implements the SHAvite-384 digest algorithm under the
 * [Digest] API (in the SHAvite-3 specification, this function
 * is known as "SHAvite-3 with a 384-bit output").
 *
 * @version   $Revision: 222 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class SHAvite384 : SHAviteBigCore() {

    override val initVal: IntArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 48

    override fun copy(): Digest {
        return copyState(SHAvite384())
    }

    companion object {
        /** The initial value for SHAvite-384.  */
        private val initVal = intArrayOf(
            -0x7c20eabb, -0x65513ed, -0xb7fc350, 0x11FE1F47,
            -0x25932d97, 0x4F53FCD7, -0x6afad65e, -0x686f7eb9,
            -0x4f5b2851, 0x2B9132BF, 0x226E607D, 0x3C0F8D7C,
            0x487B3F0F, 0x04363E22, 0x0155C99C, -0x13d1df2d
        )
    }
}
