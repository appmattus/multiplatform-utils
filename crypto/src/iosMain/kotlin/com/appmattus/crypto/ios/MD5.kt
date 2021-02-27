package com.appmattus.crypto.ios

import com.appmattus.crypto.Digest
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
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
internal class MD5 private constructor(private val hashObject: CC_MD5_CTX) : Digest<MD5> {

    constructor() : this(nativeHeap.alloc()) {
        reset()
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
                CC_MD5_Update(hashObject.ptr, it.addressOf(offset), length.toUInt())
            }
        }
    }

    override fun digest(): ByteArray {
        val digest = UByteArray(CC_MD5_DIGEST_LENGTH)

        digest.usePinned {
            CC_MD5_Final(it.addressOf(0), hashObject.ptr)
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
        CC_MD5_Init(hashObject.ptr)
    }

    override fun copy(): MD5 = MD5(
        hashObject = nativeHeap.alloc {
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
    )

    override val blockLength: Int
        get() = 64

    override fun toString() = "MD5"
}
