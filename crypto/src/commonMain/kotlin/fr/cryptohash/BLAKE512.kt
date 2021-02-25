// $Id: BLAKE512.java 252 2011-06-07 17:55:14Z tp $
package fr.cryptohash

/**
 *
 * This class implements the BLAKE-512 digest algorithm under the
 * [Digest] API.
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
 * @version   $Revision: 252 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class BLAKE512
/**
 * Create the engine.
 */
    : BLAKEBigCore() {
    /** @see BLAKESmallCore
     */
    override val initVal: LongArray
        get() = Companion.initVal

    /** @see Digest
     */
    override val digestLength: Int
        get() = 64

    /** @see Digest
     */
    override fun copy(): Digest {
        return copyState(BLAKE512())
    }

    companion object {
        /** The initial value for BLAKE-512.  */
        private val initVal = longArrayOf(
            0x6A09E667F3BCC908L, -0x4498517a7b3558c5L,
            0x3C6EF372FE94F82BL, -0x5ab00ac5a0e2c90fL,
            0x510E527FADE682D1L, -0x64fa9773d4c193e1L,
            0x1F83D9ABFB41BD6BL, 0x5BE0CD19137E2179L
        )
    }
}