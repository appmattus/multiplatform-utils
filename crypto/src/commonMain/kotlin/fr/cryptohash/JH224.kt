// $Id: JH224.java 255 2011-06-07 19:50:20Z tp $
package fr.cryptohash

/**
 *
 * This class implements the JH-224 digest algorithm under the
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
 * @version   $Revision: 255 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class JH224
/**
 * Create the engine.
 */
    : JHCore() {
    /** @see Digest
     */
    override fun copy(): Digest {
        return copyState(JH224())
    }

    override val iV: LongArray
        get() = Companion.iV

    /** @see Digest
     */
    override val digestLength: Int
        get() = 28

    companion object {
        /** @see JHCore
         */
        val iV = longArrayOf(
            0x2dfedd62f99a98acL, -0x51835329e629cb19L,
            -0x5b7ceffa43cfedeaL, -0x479fc7393699eb6cL,
            0x66d9899f2580706fL, -0x31615ce4e264e524L,
            0x11e8325f7b366e10L, -0x66b7a80fd05f93fL,
            0x1b4f1b5cd8c840b3L, -0x68095e80918c7f67L,
            -0x23206c5a52155c2dL, -0x5bce172136ac6598L,
            0x22b4a98aec86a1e4L, -0x2a8b536a631a9310L,
            0x15960deab5ab2bbfL, -0x69ee230f229b1592L
        )
    }
}