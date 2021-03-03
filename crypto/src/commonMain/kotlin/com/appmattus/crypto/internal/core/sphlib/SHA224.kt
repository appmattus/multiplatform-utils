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

import com.appmattus.crypto.Algorithm

/**
 *
 * This class implements the SHA-224 digest algorithm under the
 * [Digest] API. SHA-224 is specified by FIPS 180-2.
 *
 * @version   $Revision: 156 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
internal class SHA224 : SHA2Core<SHA224>() {

    override val initVal: IntArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 28

    override val blockLength: Int
        get() = Algorithm.SHA_224.blockLength

    override fun copy(): SHA224 {
        return copyState(SHA224())
    }

    override fun toString() = Algorithm.SHA_224.algorithmName

    companion object {
        /** The initial value for SHA-224.  */
        private val initVal = intArrayOf(
            -0x3efa6128, 0x367CD507, 0x3070DD17, -0x8f1a6c7,
            -0x3ff4cf, 0x68581511, 0x64F98FA7, -0x4105b05c
        )
    }
}