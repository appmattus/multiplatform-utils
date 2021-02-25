// $Id: CubeHash384.java 183 2010-05-08 21:34:53Z tp $
package fr.cryptohash

/**
 *
 * This class implements the CubeHash-384 digest algorithm under the
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
 * @version   $Revision: 183 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class CubeHash384
/**
 * Create the engine.
 */
    : CubeHashCore() {
    /** @see Digest
     */
    override fun copy(): Digest {
        return copyState(CubeHash384())
    }

    override val iV: IntArray
        get() = Companion.iV

    /** @see Digest
     */
    override val digestLength: Int
        get() = 48

    companion object {
        /** @see CubeHashCore
         */
        val iV = intArrayOf(
            -0x19dcf782, 0x04C00C87, 0x5EF46453,
            0x69524B13, 0x1A05C7A9, 0x3528DF88,
            0x6BDD01B5, 0x5057B792, 0x6AA7A922,
            0x649C7EEE, -0xbd9cf61, -0x349d6fae,
            -0x371df13, -0x4cb7d455, -0x761a182,
            -0x27c2b21c, 0x44BFC10D, 0x5FC1E63D,
            0x2104E6CB, 0x17958F7F, -0x24151090,
            -0x4b4681e2, 0x32C195F6, 0x6184A8E4,
            0x796C2543, 0x23DE176D, -0x2cc44514,
            0x0C12E5D2, 0x4EB95A7B, 0x2D18BA01,
            0x04EE475F, 0x1FC5F22E
        )
    }
}
