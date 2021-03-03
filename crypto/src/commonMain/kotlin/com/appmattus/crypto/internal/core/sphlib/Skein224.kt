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
 * This class implements the Skein-224 digest algorithm under the
 * [Digest] API. In the Skein specification, that function is
 * called under the full name "Skein-512-224".
 *
 * @version   $Revision: 253 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Skein224 : SkeinBigCore<Skein224>() {

    override val initVal: LongArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 28

    override fun dup(): Skein224 {
        return Skein224()
    }

    companion object {
        /** The initial value for Skein-224.  */
        private val initVal = longArrayOf(
            -0x332f9e9db7988ddcL, -0x3459a30c56dcc611L,
            -0x73329629ad00b49cL, 0x398AED7B3AB890B4L,
            0x0F59D1B1457D2BD0L, 0x6776FE6575D4EB3DL,
            -0x660438f1668bec17L, -0x61d303301e3be109L
        )
    }
}
