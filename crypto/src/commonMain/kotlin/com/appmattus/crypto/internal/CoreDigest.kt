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

package com.appmattus.crypto.internal

import com.appmattus.crypto.Algorithm
import com.appmattus.crypto.Digest
import com.appmattus.crypto.internal.core.SHA512_224
import com.appmattus.crypto.internal.core.SHA512_256
import fr.cryptohash.MD2
import fr.cryptohash.MD4
import fr.cryptohash.MD5
import fr.cryptohash.SHA1
import fr.cryptohash.SHA224
import fr.cryptohash.SHA256
import fr.cryptohash.SHA384
import fr.cryptohash.SHA512

internal object CoreDigest {
    fun create(algorithm: Algorithm): Digest<*> {
        return when (algorithm) {
            Algorithm.MD2 -> MD2()
            Algorithm.MD4 -> MD4()
            Algorithm.MD5 -> MD5()
            Algorithm.SHA_1 -> SHA1()
            Algorithm.SHA_224 -> SHA224()
            Algorithm.SHA_256 -> SHA256()
            Algorithm.SHA_384 -> SHA384()
            Algorithm.SHA_512 -> SHA512()
            Algorithm.SHA_512_224 -> SHA512_224()
            Algorithm.SHA_512_256 -> SHA512_256()
            Algorithm.SHA3_224 -> TODO()
            Algorithm.SHA3_256 -> TODO()
            Algorithm.SHA3_384 -> TODO()
            Algorithm.SHA3_512 -> TODO()
        }
    }
}
