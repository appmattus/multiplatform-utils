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
 * This class implements the Skein-256 digest algorithm under the
 * [Digest] API. In the Skein specification, that function is
 * called under the full name "Skein-512-256".
 *
 * @version   $Revision: 253 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
@Suppress("ClassName")
internal class Skein512_256 : SkeinBigCore<Skein512_256>() {

    override val initVal: LongArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 32

    override fun dup(): Skein512_256 {
        return Skein512_256()
    }

    companion object {
        /** The initial value for Skein-256.  */
        private val initVal = longArrayOf(
            -0x332fbb5ed024c1edL, -0x17ca6fcfe5865615L,
            0x55AEA0614F816E6FL, 0x2A2767A4AE9B94DBL,
            -0x13f9fda18b22897dL, -0x185bc9323b8b9dafL,
            -0x3c904506c6c52e7bL, 0x3EEDBA1833EDFC13L
        )
    }
}
