// $Id: SHA384.java 156 2010-04-26 17:55:11Z tp $
package fr.cryptohash

/**
 *
 * This class implements the SHA-384 digest algorithm under the
 * [Digest] API. SHA-384 is specified by FIPS 180-2.
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
 * @version   $Revision: 156 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class SHA384
/**
 * Create the engine.
 */
    : SHA2BigCore() {
    /** @see SHA2BigCore
     */
    override val initVal: LongArray
        get() = Companion.initVal

    /** @see Digest
     */
    override val digestLength: Int
        get() = 48

    /** @see Digest
     */
    override fun copy(): Digest {
        return copyState(SHA384())
    }

    companion object {
        /** The initial value for SHA-384.  */
        private val initVal = longArrayOf(
            -0x344462a23efa6128L, 0x629A292A367CD507L,
            -0x6ea6fea5cf8f22e9L, 0x152FECD8F70E5939L,
            0x67332667FFC00B31L, -0x714bb57897a7eaefL,
            -0x24f3d1f29b067059L, 0x47B5481DBEFA4FA4L
        )
    }
}
