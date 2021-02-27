package com.appmattus.crypto.ios

import com.appmattus.crypto.Digest
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.free
import kotlinx.cinterop.get
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.ptr
import kotlinx.cinterop.set
import kotlinx.cinterop.usePinned
import platform.CoreCrypto.CC_MD5_BLOCK_LONG
import platform.CoreCrypto.CC_MD5_CTX
import platform.CoreCrypto.CC_MD5_DIGEST_LENGTH
import platform.CoreCrypto.CC_MD5_Final
import platform.CoreCrypto.CC_MD5_Init
import platform.CoreCrypto.CC_MD5_Update

@Suppress("EXPERIMENTAL_API_USAGE")
internal class MD5 : Digest<MD5> {

    private var hashObject: CC_MD5_CTX? = null

    private val hashObjectPtr: CPointer<CC_MD5_CTX>
        get() = hashObject?.ptr ?: nativeHeap.alloc<CC_MD5_CTX>().run {
            hashObject = this
            CC_MD5_Init(ptr)
            ptr
        }

    override fun update(input: Byte) {
        update(ByteArray(1) { input })
    }

    override fun update(input: ByteArray) {
        update(input, 0, input.size)
    }

    override fun update(input: ByteArray, offset: Int, length: Int) {
        if (length > 0) {
            input.usePinned {
                CC_MD5_Update(hashObjectPtr, it.addressOf(offset), length.toUInt())
            }
        }
    }

    override fun digest(): ByteArray {
        val digest = UByteArray(CC_MD5_DIGEST_LENGTH)

        digest.usePinned {
            CC_MD5_Final(it.addressOf(0), hashObjectPtr)
        }

        reset()

        return digest.toByteArray()
    }

    override fun digest(input: ByteArray): ByteArray {
        update(input)
        return digest()
    }

    override fun digest(output: ByteArray, offset: Int, length: Int): Int {
        TODO("Not yet implemented")
    }

    override val digestLength: Int
        get() = CC_MD5_DIGEST_LENGTH

    override fun reset() {
        hashObject?.let { nativeHeap.free(it) }
        hashObject = null
    }

    override fun copy(): MD5 {
        val digest = MD5()

        hashObject?.let { hashObject ->
            digest.hashObject = nativeHeap.alloc {
                A = hashObject.A
                B = hashObject.B
                C = hashObject.C
                D = hashObject.D
                Nh = hashObject.Nh
                Nl = hashObject.Nl

                for (i in 0..CC_MD5_BLOCK_LONG.toInt()) {
                    data[i] = hashObject.data[i]
                }
            }
        }
        return digest
    }

    override val blockLength: Int
        get() = 64

    override fun toString() = "MD5"
}
