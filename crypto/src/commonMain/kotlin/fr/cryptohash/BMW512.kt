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
 * This class implements the BMW-512 ("Blue Midnight Wish") digest
 * algorithm under the [Digest] API.
 *
 * @version   $Revision: 166 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class BMW512 : BMWBigCore() {

    override val initVal: LongArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 64

    override fun copy(): Digest {
        return copyState(BMW512())
    }

    companion object {
        /** The initial value for BMW-512.  */
        private val initVal = longArrayOf(
            -0x7f7e7d7c7b7a7979L, -0x7776757473727171L,
            -0x6f6e6d6c6b6a6969L, -0x6766656463626161L,
            -0x5f5e5d5c5b5a5959L, -0x5756555453525151L,
            -0x4f4e4d4c4b4a4949L, -0x4746454443424141L,
            -0x3f3e3d3c3b3a3939L, -0x3736353433323131L,
            -0x2f2e2d2c2b2a2929L, -0x2726252423222121L,
            -0x1f1e1d1c1b1a1919L, -0x1716151413121111L,
            -0xf0e0d0c0b0a0909L, -0x706050403020101L
        )
    }
}
