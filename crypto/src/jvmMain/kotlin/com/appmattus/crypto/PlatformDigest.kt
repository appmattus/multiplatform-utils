/*
 * Copyright 2021 Appmattus Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.appmattus.crypto

import com.appmattus.crypto.jvm.MessageDigestPlatform

internal actual class PlatformDigest {

    actual fun createDigest(algorithm: Algorithm): Digest<*>? {
        return when (algorithm) {
            Algorithm.MD2 -> MessageDigestPlatform("MD2", algorithm.blockLength)
            Algorithm.MD5 -> MessageDigestPlatform("MD5", algorithm.blockLength)
            Algorithm.SHA_1 -> MessageDigestPlatform("SHA-1", algorithm.blockLength)
            Algorithm.SHA_224 -> MessageDigestPlatform("SHA-224", algorithm.blockLength)
            Algorithm.SHA_256 -> MessageDigestPlatform("SHA-256", algorithm.blockLength)
            Algorithm.SHA_384 -> MessageDigestPlatform("SHA-384", algorithm.blockLength)
            Algorithm.SHA_512 -> MessageDigestPlatform("SHA-512", algorithm.blockLength)

            Algorithm.SHA_512_224 -> MessageDigestPlatform("SHA-512/224", algorithm.blockLength)
            Algorithm.SHA_512_256 -> MessageDigestPlatform("SHA-512/256", algorithm.blockLength)

            Algorithm.SHA3_224 -> MessageDigestPlatform("SHA3-224", algorithm.blockLength)
            Algorithm.SHA3_256 -> MessageDigestPlatform("SHA3-256", algorithm.blockLength)
            Algorithm.SHA3_384 -> MessageDigestPlatform("SHA3-384", algorithm.blockLength)
            Algorithm.SHA3_512 -> MessageDigestPlatform("SHA3-512", algorithm.blockLength)

            else -> null
        }
    }
}
