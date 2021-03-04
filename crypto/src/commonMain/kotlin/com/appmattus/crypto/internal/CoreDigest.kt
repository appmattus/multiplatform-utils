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
import com.appmattus.crypto.internal.core.Adler32
import com.appmattus.crypto.internal.core.CRC32
import com.appmattus.crypto.internal.core.Keccak288
import com.appmattus.crypto.internal.core.RipeMD256
import com.appmattus.crypto.internal.core.RipeMD320
import com.appmattus.crypto.internal.core.SHA3_224
import com.appmattus.crypto.internal.core.SHA3_256
import com.appmattus.crypto.internal.core.SHA3_384
import com.appmattus.crypto.internal.core.SHA3_512
import com.appmattus.crypto.internal.core.SHA512_224
import com.appmattus.crypto.internal.core.SHA512_256
import com.appmattus.crypto.internal.core.bouncycastle.GOST3411_2012_256
import com.appmattus.crypto.internal.core.bouncycastle.GOST3411_2012_512
import com.appmattus.crypto.internal.core.sphlib.Keccak224
import com.appmattus.crypto.internal.core.sphlib.Keccak256
import com.appmattus.crypto.internal.core.sphlib.Keccak384
import com.appmattus.crypto.internal.core.sphlib.Keccak512
import com.appmattus.crypto.internal.core.sphlib.MD2
import com.appmattus.crypto.internal.core.sphlib.MD4
import com.appmattus.crypto.internal.core.sphlib.MD5
import com.appmattus.crypto.internal.core.sphlib.RipeMD
import com.appmattus.crypto.internal.core.sphlib.RipeMD128
import com.appmattus.crypto.internal.core.sphlib.RipeMD160
import com.appmattus.crypto.internal.core.sphlib.SHA0
import com.appmattus.crypto.internal.core.sphlib.SHA1
import com.appmattus.crypto.internal.core.sphlib.SHA224
import com.appmattus.crypto.internal.core.sphlib.SHA256
import com.appmattus.crypto.internal.core.sphlib.SHA384
import com.appmattus.crypto.internal.core.sphlib.SHA512
import com.appmattus.crypto.internal.core.sphlib.Tiger
import com.appmattus.crypto.internal.core.sphlib.Tiger2
import com.appmattus.crypto.internal.core.sphlib.Whirlpool
import com.appmattus.crypto.internal.core.sphlib.Whirlpool0
import com.appmattus.crypto.internal.core.sphlib.WhirlpoolT

internal object CoreDigest {
    fun create(algorithm: Algorithm): Digest<*> {
        return when (algorithm) {
            Algorithm.MD2 -> MD2()
            Algorithm.MD4 -> MD4()
            Algorithm.MD5 -> MD5()

            Algorithm.SHA_0 -> SHA0()
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

            Algorithm.RipeMD -> RipeMD()
            Algorithm.RipeMD128 -> RipeMD128()
            Algorithm.RipeMD160 -> RipeMD160()
            Algorithm.RipeMD256 -> RipeMD256()
            Algorithm.RipeMD320 -> RipeMD320()

            Algorithm.Tiger -> Tiger()
            Algorithm.Tiger2 -> Tiger2()

            Algorithm.Adler32 -> Adler32()
            Algorithm.CRC32 -> CRC32()

            Algorithm.GOST3411_2012_256 -> GOST3411_2012_256()
            Algorithm.GOST3411_2012_512 -> GOST3411_2012_512()

            Algorithm.Whirlpool -> Whirlpool()
            Algorithm.Whirlpool0 -> Whirlpool0()
            Algorithm.WhirlpoolT -> WhirlpoolT()
        }
    }
}
