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
 * This class implements the Skein-384 digest algorithm under the
 * [Digest] API. In the Skein specification, that function is
 * called under the full name "Skein-512-384".
 *
 * @version   $Revision: 253 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("ClassName")
internal class Skein512_384 : SkeinBigCore<Skein512_384>() {

    override val initVal: LongArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 48

    override fun dup(): Skein512_384 {
        return Skein512_384()
    }

    companion object {
        /** The initial value for Skein-384.  */
        private val initVal = longArrayOf(
            -0x5c093940c58a10a1L, -0x4f010633027b055cL,
            -0x62882299c288f302L, -0x2867340c4b970226L,
            0x1BC4A6668A0E4465L, 0x7ED7D434E5807407L,
            0x548FC1ACD4EC44D6L, 0x266E17546AA18FF8L
        )
    }
}
