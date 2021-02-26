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
 * This class implements the SIMD-224 digest algorithm under the
 * [Digest] API.
 *
 * @version   $Revision: 156 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class SIMD224 : SIMDSmallCore<SIMD224>() {

    override val initVal: IntArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 28

    override fun copy(): SIMD224 {
        return copyState(SIMD224())
    }

    companion object {
        /** The initial value for SIMD-224.  */
        private val initVal = intArrayOf(
            0x33586E9F, 0x12FFF033, -0x4d2609b3, 0x6F8FEA53,
            -0x216bcefa, 0x2742E439, 0x4FBAB5AC, 0x62B9FF96,
            0x22E7B0AF, -0x379d4c58, 0x33E00CDC, 0x236B86A6,
            -0x9b51884, -0x5c8c48a, 0x7DC1EE5B, 0x7FB29CE8
        )
    }
}
