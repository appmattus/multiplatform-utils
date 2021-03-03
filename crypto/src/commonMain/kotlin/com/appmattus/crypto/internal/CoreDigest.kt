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
import com.appmattus.crypto.internal.core.Keccak288
import com.appmattus.crypto.internal.core.RIPEMD256
import com.appmattus.crypto.internal.core.RIPEMD320
import com.appmattus.crypto.internal.core.SHA3_224
import com.appmattus.crypto.internal.core.SHA3_256
import com.appmattus.crypto.internal.core.SHA3_384
import com.appmattus.crypto.internal.core.SHA3_512
import com.appmattus.crypto.internal.core.SHA512_224
import com.appmattus.crypto.internal.core.SHA512_256
import fr.cryptohash.Keccak224
import fr.cryptohash.Keccak256
import fr.cryptohash.Keccak384
import fr.cryptohash.Keccak512
import fr.cryptohash.MD2
import fr.cryptohash.MD4
import fr.cryptohash.MD5
import fr.cryptohash.RIPEMD128
import fr.cryptohash.RIPEMD160
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

            Algorithm.SHA3_224 -> SHA3_224()
            Algorithm.SHA3_256 -> SHA3_256()
            Algorithm.SHA3_384 -> SHA3_384()
            Algorithm.SHA3_512 -> SHA3_512()

            Algorithm.Keccak224 -> Keccak224()
            Algorithm.Keccak256 -> Keccak256()
            Algorithm.Keccak288 -> Keccak288()
            Algorithm.Keccak384 -> Keccak384()
            Algorithm.Keccak512 -> Keccak512()

            Algorithm.RIPEMD128 -> RIPEMD128()
            Algorithm.RIPEMD160 -> RIPEMD160()
            Algorithm.RIPEMD256 -> RIPEMD256()
            Algorithm.RIPEMD320 -> RIPEMD320()
        }
    }
}
