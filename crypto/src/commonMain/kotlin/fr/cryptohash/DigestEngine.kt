// $Id: DigestEngine.java 229 2010-06-16 20:22:27Z tp $
package fr.cryptohash

/**
 *
 * This class is a template which can be used to implement hash
 * functions. It takes care of some of the API, and also provides an
 * internal data buffer whose length is equal to the hash function
 * internal block length.
 *
 *
 * Classes which use this template MUST provide a working [ ][.getBlockLength] method even before initialization (alternatively,
 * they may define a custom [.getInternalBlockLength] which does
 * not call [.getBlockLength]. The [.getDigestLength] should
 * also be operational from the beginning, but it is acceptable that it
 * returns 0 while the [.doInit] method has not been called
 * yet.
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
 * @version   $Revision: 229 $
 * @author    Thomas Pornin &lt;thomas.pornin@cryptolog.com&gt;
 */
abstract class DigestEngine : Digest {
    /**
     * Reset the hash algorithm state.
     */
    protected abstract fun engineReset()

    /**
     * Process one block of data.
     *
     * @param data   the data block
     */
    protected abstract fun processBlock(data: ByteArray)

    /**
     * Perform the final padding and store the result in the
     * provided buffer. This method shall call [.flush]
     * and then [.update] with the appropriate padding
     * data in order to get the full input data.
     *
     * @param buf   the output buffer
     * @param off   the output offset
     */
    protected abstract fun doPadding(buf: ByteArray, off: Int)

    /**
     * This function is called at object creation time; the
     * implementation should use it to perform initialization tasks.
     * After this method is called, the implementation should be ready
     * to process data or meaningfully honour calls such as
     * [.getDigestLength].
     */
    protected abstract fun doInit()
    private var digestLen: Int
    private val blockLen: Int
    private var inputLen: Int

    /**
     * Get a reference to an internal buffer with the same size
     * than a block. The contents of that buffer are defined only
     * immediately after a call to [.flush]: if
     * [.flush] return the value `n`, then the
     * first `n` bytes of the array returned by this method
     * are the `n` bytes of input data which are still
     * unprocessed. The values of the remaining bytes are
     * undefined and may be altered at will.
     *
     * @return  a block-sized internal buffer
     */
    protected val blockBuffer: ByteArray
    private var outputBuf: ByteArray

    /**
     * Get the "block count": this is the number of times the
     * [.processBlock] method has been invoked for the
     * current hash operation. That counter is incremented
     * *after* the call to [.processBlock].
     *
     * @return  the block count
     */
    protected var blockCount: Long
        private set

    private fun adjustDigestLen() {
        if (digestLen == 0) {
            digestLen = digestLength
            outputBuf = ByteArray(digestLen)
        }
    }

    /** @see Digest
     */
    override fun digest(): ByteArray {
        adjustDigestLen()
        val result = ByteArray(digestLen)
        digest(result, 0, digestLen)
        return result
    }

    /** @see Digest
     */
    override fun digest(input: ByteArray): ByteArray {
        update(input, 0, input.size)
        return digest()
    }

    /** @see Digest
     */
    override fun digest(buf: ByteArray, offset: Int, len: Int): Int {
        adjustDigestLen()
        return if (len >= digestLen) {
            doPadding(buf, offset)
            reset()
            digestLen
        } else {
            doPadding(outputBuf, 0)
            outputBuf.copyInto(buf, offset, 0, len)
            //java.lang.System.arraycopy(outputBuf, 0, buf, offset, len)
            reset()
            len
        }
    }

    /** @see Digest
     */
    override fun reset() {
        engineReset()
        inputLen = 0
        blockCount = 0
    }

    /** @see Digest
     */
    override fun update(input: Byte) {
        blockBuffer[inputLen++] = input
        if (inputLen == blockLen) {
            processBlock(blockBuffer)
            blockCount++
            inputLen = 0
        }
    }

    /** @see Digest
     */
    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    /** @see Digest
     */
    override fun update(input: ByteArray, offset: Int, len: Int) {
        var offset = offset
        var len = len
        while (len > 0) {
            var copyLen = blockLen - inputLen
            if (copyLen > len) copyLen = len
            input.copyInto(blockBuffer, inputLen, offset, offset + copyLen)

            offset += copyLen
            inputLen += copyLen
            len -= copyLen
            if (inputLen == blockLen) {
                processBlock(blockBuffer)
                blockCount++
                inputLen = 0
            }
        }
    }

    /**
     * Flush internal buffers, so that less than a block of data
     * may at most be upheld.
     *
     * @return  the number of bytes still unprocessed after the flush
     */
    protected fun flush(): Int {
        return inputLen
    }

    /**
     * This function copies the internal buffering state to some
     * other instance of a class extending `DigestEngine`.
     * It returns a reference to the copy. This method is intended
     * to be called by the implementation of the [.copy]
     * method.
     *
     * @param dest   the copy
     * @return  the value `dest`
     */
    protected fun copyState(dest: DigestEngine): Digest {
        dest.inputLen = inputLen
        dest.blockCount = blockCount
        blockBuffer.copyInto(dest.blockBuffer, 0, 0, blockBuffer.size)
        adjustDigestLen()
        dest.adjustDigestLen()
        outputBuf.copyInto(dest.outputBuf, 0, 0, outputBuf.size)
        return dest
    }

    /**
     * Instantiate the engine.
     */
    init {
        doInit()
        digestLen = digestLength
        blockLen = blockLength
        blockBuffer = ByteArray(blockLen)
        outputBuf = ByteArray(digestLen)
        inputLen = 0
        blockCount = 0
    }
}
