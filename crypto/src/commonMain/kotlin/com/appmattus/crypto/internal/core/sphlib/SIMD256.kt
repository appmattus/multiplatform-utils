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

package com.appmattus.crypto.internal.core.sphlib

/**
 *
 * This class implements the SIMD-256 digest algorithm under the
 * [Digest] API.
 *
 * @version   $Revision: 156 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class SIMD256 : SIMDSmallCore<SIMD256>() {

    override val initVal: IntArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 32

    override fun copy(): SIMD256 {
        return copyState(SIMD256())
    }

    companion object {
        /** The initial value for SIMD-256.  */
        private val initVal = intArrayOf(
            0x4D567983, 0x07190BA9, -0x7b8ba885, 0x39D726E9,
            -0x550c26db, 0x3EE20B03, -0x502a18af, -0x369ff92d,
            -0x3d3d45ec, 0x49B3BCB4, -0x98350ba, 0x668626C9,
            -0x1d15572e, 0x1FF47833, -0x2f399e5b, 0x55693DE1
        )
    }
}