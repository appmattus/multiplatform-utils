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
import com.appmattus.crypto.internal.core.sphlib.BLAKE224
import com.appmattus.crypto.internal.core.sphlib.BLAKE256
import com.appmattus.crypto.internal.core.sphlib.BLAKE384
import com.appmattus.crypto.internal.core.sphlib.BLAKE512
import com.appmattus.crypto.internal.core.sphlib.BMW224
import com.appmattus.crypto.internal.core.sphlib.BMW256
import com.appmattus.crypto.internal.core.sphlib.BMW384
import com.appmattus.crypto.internal.core.sphlib.BMW512
import com.appmattus.crypto.internal.core.sphlib.CubeHash224
import com.appmattus.crypto.internal.core.sphlib.CubeHash256
import com.appmattus.crypto.internal.core.sphlib.CubeHash384
import com.appmattus.crypto.internal.core.sphlib.CubeHash512
import com.appmattus.crypto.internal.core.sphlib.ECHO224
import com.appmattus.crypto.internal.core.sphlib.ECHO256
import com.appmattus.crypto.internal.core.sphlib.ECHO384
import com.appmattus.crypto.internal.core.sphlib.ECHO512
import com.appmattus.crypto.internal.core.sphlib.Fugue224
import com.appmattus.crypto.internal.core.sphlib.Fugue256
import com.appmattus.crypto.internal.core.sphlib.Fugue384
import com.appmattus.crypto.internal.core.sphlib.Fugue512
import com.appmattus.crypto.internal.core.sphlib.Groestl224
import com.appmattus.crypto.internal.core.sphlib.Groestl256
import com.appmattus.crypto.internal.core.sphlib.Groestl384
import com.appmattus.crypto.internal.core.sphlib.Groestl512
import com.appmattus.crypto.internal.core.sphlib.Hamsi224
import com.appmattus.crypto.internal.core.sphlib.Hamsi256
import com.appmattus.crypto.internal.core.sphlib.Hamsi384
import com.appmattus.crypto.internal.core.sphlib.Hamsi512
import com.appmattus.crypto.internal.core.sphlib.Keccak224
import com.appmattus.crypto.internal.core.sphlib.Keccak256
import com.appmattus.crypto.internal.core.sphlib.Keccak384
import com.appmattus.crypto.internal.core.sphlib.Keccak512
import com.appmattus.crypto.internal.core.sphlib.Luffa224
import com.appmattus.crypto.internal.core.sphlib.Luffa256
import com.appmattus.crypto.internal.core.sphlib.Luffa384
import com.appmattus.crypto.internal.core.sphlib.Luffa512
import com.appmattus.crypto.internal.core.sphlib.MD2
import com.appmattus.crypto.internal.core.sphlib.MD4
import com.appmattus.crypto.internal.core.sphlib.MD5
import com.appmattus.crypto.internal.core.sphlib.PANAMA
import com.appmattus.crypto.internal.core.sphlib.RadioGatun32
import com.appmattus.crypto.internal.core.sphlib.RadioGatun64
import com.appmattus.crypto.internal.core.sphlib.RipeMD
import com.appmattus.crypto.internal.core.sphlib.RipeMD128
import com.appmattus.crypto.internal.core.sphlib.RipeMD160
import com.appmattus.crypto.internal.core.sphlib.SHA0
import com.appmattus.crypto.internal.core.sphlib.SHA1
import com.appmattus.crypto.internal.core.sphlib.SHA224
import com.appmattus.crypto.internal.core.sphlib.SHA256
import com.appmattus.crypto.internal.core.sphlib.SHA384
import com.appmattus.crypto.internal.core.sphlib.SHA512
import com.appmattus.crypto.internal.core.sphlib.SHAvite224
import com.appmattus.crypto.internal.core.sphlib.SHAvite256
import com.appmattus.crypto.internal.core.sphlib.SHAvite384
import com.appmattus.crypto.internal.core.sphlib.SHAvite512
import com.appmattus.crypto.internal.core.sphlib.SIMD224
import com.appmattus.crypto.internal.core.sphlib.SIMD256
import com.appmattus.crypto.internal.core.sphlib.SIMD384
import com.appmattus.crypto.internal.core.sphlib.SIMD512
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

            Algorithm.BLAKE224 -> BLAKE224()
            Algorithm.BLAKE256 -> BLAKE256()
            Algorithm.BLAKE384 -> BLAKE384()
            Algorithm.BLAKE512 -> BLAKE512()

            Algorithm.BMW224 -> BMW224()
            Algorithm.BMW256 -> BMW256()
            Algorithm.BMW384 -> BMW384()
            Algorithm.BMW512 -> BMW512()

            Algorithm.CubeHash224 -> CubeHash224()
            Algorithm.CubeHash256 -> CubeHash256()
            Algorithm.CubeHash384 -> CubeHash384()
            Algorithm.CubeHash512 -> CubeHash512()

            Algorithm.ECHO224 -> ECHO224()
            Algorithm.ECHO256 -> ECHO256()
            Algorithm.ECHO384 -> ECHO384()
            Algorithm.ECHO512 -> ECHO512()

            Algorithm.Fugue224 -> Fugue224()
            Algorithm.Fugue256 -> Fugue256()
            Algorithm.Fugue384 -> Fugue384()
            Algorithm.Fugue512 -> Fugue512()

            Algorithm.Groestl224 -> Groestl224()
            Algorithm.Groestl256 -> Groestl256()
            Algorithm.Groestl384 -> Groestl384()
            Algorithm.Groestl512 -> Groestl512()

            Algorithm.Hamsi224 -> Hamsi224()
            Algorithm.Hamsi256 -> Hamsi256()
            Algorithm.Hamsi384 -> Hamsi384()
            Algorithm.Hamsi512 -> Hamsi512()

            Algorithm.Luffa224 -> Luffa224()
            Algorithm.Luffa256 -> Luffa256()
            Algorithm.Luffa384 -> Luffa384()
            Algorithm.Luffa512 -> Luffa512()

            Algorithm.SHAvite224 -> SHAvite224()
            Algorithm.SHAvite256 -> SHAvite256()
            Algorithm.SHAvite384 -> SHAvite384()
            Algorithm.SHAvite512 -> SHAvite512()

            Algorithm.SIMD224 -> SIMD224()
            Algorithm.SIMD256 -> SIMD256()
            Algorithm.SIMD384 -> SIMD384()
            Algorithm.SIMD512 -> SIMD512()

            Algorithm.RadioGatun32 -> RadioGatun32()
            Algorithm.RadioGatun64 -> RadioGatun64()

            Algorithm.PANAMA -> PANAMA()

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
