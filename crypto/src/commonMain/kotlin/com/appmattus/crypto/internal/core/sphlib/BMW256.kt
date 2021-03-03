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
 * This class implements the BMW-256 ("Blue Midnight Wish") digest
 * algorithm under the [Digest] API.
 *
 * @version   $Revision: 166 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class BMW256 : BMWSmallCore<BMW256>() {

    override val initVal: IntArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 32

    override fun copy(): BMW256 {
        return copyState(BMW256())
    }

    companion object {
        /** The initial value for BMW-256.  */
        private val initVal = intArrayOf(
            0x40414243, 0x44454647, 0x48494A4B, 0x4C4D4E4F,
            0x50515253, 0x54555657, 0x58595A5B, 0x5C5D5E5F,
            0x60616263, 0x64656667, 0x68696A6B, 0x6C6D6E6F,
            0x70717273, 0x74757677, 0x78797A7B, 0x7C7D7E7F
        )
    }
}