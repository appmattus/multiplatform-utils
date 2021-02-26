// $Id: Digest.java 232 2010-06-17 14:19:24Z tp $
package fr.cryptohash

/**
 *
 * This interface documents the API for a hash function. This
 * interface somewhat mimics the standard `java.security.MessageDigest` class. We do not extend that class in
 * order to provide compatibility with reduced Java implementations such
 * as J2ME. Implementing a `java.security.Provider` compatible
 * with Sun's JCA ought to be easy.
 *
 *
 * A `Digest` object maintains a running state for a hash
 * function computation. Data is inserted with `update()` calls;
 * the result is obtained from a `digest()` method (where some
 * final data can be inserted as well). When a digest output has been
 * produced, the objet is automatically resetted, and can be used
 * immediately for another digest operation. The state of a computation
 * can be cloned with the [.copy] method; this can be used to get
 * a partial hash result without interrupting the complete
 * computation.
 *
 *
 * `Digest` objects are stateful and hence not thread-safe;
 * however, distinct `Digest` objects can be accessed concurrently
 * without any problem.
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
 * @version   $Revision: 232 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
interface Digest {
    /**
     * Insert one more input data byte.
     *
     * @param in   the input byte
     */
    fun update(`in`: Byte)

    /**
     * Insert some more bytes.
     *
     * @param inbuf   the data bytes
     */
    fun update(inbuf: ByteArray)

    /**
     * Insert some more bytes.
     *
     * @param inbuf   the data buffer
     * @param off     the data offset in `inbuf`
     * @param len     the data length (in bytes)
     */
    fun update(inbuf: ByteArray, off: Int, len: Int)

    /**
     * Finalize the current hash computation and return the hash value
     * in a newly-allocated array. The object is resetted.
     *
     * @return  the hash output
     */
    fun digest(): ByteArray

    /**
     * Input some bytes, then finalize the current hash computation
     * and return the hash value in a newly-allocated array. The object
     * is resetted.
     *
     * @param inbuf   the input data
     * @return  the hash output
     */
    fun digest(inbuf: ByteArray): ByteArray

    /**
     * Finalize the current hash computation and store the hash value
     * in the provided output buffer. The `len` parameter
     * contains the maximum number of bytes that should be written;
     * no more bytes than the natural hash function output length will
     * be produced. If `len` is smaller than the natural
     * hash output length, the hash output is truncated to its first
     * `len` bytes. The object is resetted.
     *
     * @param outbuf   the output buffer
     * @param off      the output offset within `outbuf`
     * @param len      the requested hash output length (in bytes)
     * @return  the number of bytes actually written in `outbuf`
     */
    fun digest(outbuf: ByteArray, off: Int, len: Int): Int

    /**
     * Get the natural hash function output length (in bytes).
     *
     * @return  the digest output length (in bytes)
     */
    val digestLength: Int

    /**
     * Reset the object: this makes it suitable for a new hash
     * computation. The current computation, if any, is discarded.
     */
    fun reset()

    /**
     * Clone the current state. The returned object evolves independantly
     * of this object.
     *
     * @return  the clone
     */
    fun copy(): Digest

    /**
     * Return the "block length" for the hash function. This
     * value is naturally defined for iterated hash functions
     * (Merkle-Damgard). It is used in HMAC (that's what the
     * [HMAC specification](http://tools.ietf.org/html/rfc2104)
     * names the "`B`" parameter).
     *
     * If the function is "block-less" then this function may
     * return `-n` where `n` is an integer such that the
     * block length for HMAC ("`B`") will be inferred from the
     * key length, by selecting the smallest multiple of `n`
     * which is no smaller than the key length. For instance, for
     * the Fugue-xxx hash functions, this function returns -4: the
     * virtual block length B is the HMAC key length, rounded up to
     * the next multiple of 4.
     *
     * @return  the internal block length (in bytes), or `-n`
     */
    val blockLength: Int

    /**
     *
     * Get the display name for this function (e.g. `"SHA-1"`
     * for SHA-1).
     */
    override fun toString(): String
}
