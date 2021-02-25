// $Id: Fugue224.java 159 2010-05-01 15:41:17Z tp $
package fr.cryptohash

/**
 *
 * This class implements the Fugue-224 digest algorithm under the
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
 * @version   $Revision: 159 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Fugue224
/**
 * Create the engine.
 */
    : Fugue2Core() {
    /** @see Digest
     */
    override val digestLength: Int
        get() = 28

    override val iV: IntArray
        get() = Companion.iV

    /** @see FugueCore
     */
    override fun dup(): FugueCore {
        return Fugue224()
    }

    companion object {
        /** @see FugueCore
         */
        /** The initial value for Fugue-224.  */
        val iV = intArrayOf(
            -0xb36edf3, 0x6286f757, -0x11c61fe4, -0x1f8b1c35,
            -0x5eed839e, -0x65bc2deb, -0x42729866
        )
    }
}