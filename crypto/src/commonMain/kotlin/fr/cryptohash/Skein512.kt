// $Id: Skein512.java 253 2011-06-07 18:33:10Z tp $
package fr.cryptohash

/**
 *
 * This class implements the Skein-512 digest algorithm under the
 * [Digest] API. In the Skein specification, that function is
 * called under the full name "Skein-512-512".
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
 * @version   $Revision: 253 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
class Skein512 : SkeinBigCore() {

    override val initVal: LongArray
        get() = Companion.initVal

    override val digestLength: Int
        get() = 64

    override fun dup(): SkeinBigCore {
        return Skein512()
    }

    companion object {
        /** The initial value for Skein-512.  */
        private val initVal = longArrayOf(
            0x4903ADFF749C51CEL, 0x0D95DE399746DF03L,
            -0x702e6cbed8386432L, -0x65daa9d600cad34fL,
            0x5DB62599DF6CA7B0L, -0x1541c6b3562a3c0cL,
            -0x66eeed38e58a4addL, -0x51e75bf499f033cdL
        )
    }
}
