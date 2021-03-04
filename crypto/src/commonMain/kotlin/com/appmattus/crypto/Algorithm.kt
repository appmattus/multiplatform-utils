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

enum class Algorithm(val algorithmName: String, internal val blockLength: Int) {
    MD2("MD2", 16),
    MD4("MD4", 64),
    MD5("MD5", 64),

    SHA_0("SHA-0", 64),
    SHA_1("SHA-1", 64),
    SHA_224("SHA-224", 64),
    SHA_256("SHA-256", 64),
    SHA_384("SHA-384", 128),
    SHA_512("SHA-512", 128),
    SHA_512_224("SHA-512/224", 128),
    SHA_512_256("SHA-512/256", 128),

    SHA3_224("SHA3-224", 144),
    SHA3_256("SHA3-256", 136),
    SHA3_384("SHA3-384", 104),
    SHA3_512("SHA3-512", 72),

    Keccak224("Keccak-224", 144),
    Keccak256("Keccak-256", 136),
    Keccak288("Keccak-288", 128),
    Keccak384("Keccak-384", 104),
    Keccak512("Keccak-512", 72),

    BLAKE224("BLAKE-224", 64),
    BLAKE256("BLAKE-256", 64),
    BLAKE384("BLAKE-384", 128),
    BLAKE512("BLAKE-512", 128),

    BMW224("BMW-224", 64),
    BMW256("BMW-256", 64),
    BMW384("BMW-384", 128),
    BMW512("BMW-512", 128),

    CubeHash224("CubeHash-224", 32),
    CubeHash256("CubeHash-256", 32),
    CubeHash384("CubeHash-384", 32),
    CubeHash512("CubeHash-512", 32),

    ECHO224("ECHO-224", 192),
    ECHO256("ECHO-256", 192),
    ECHO384("ECHO-384", 128),
    ECHO512("ECHO-512", 128),

    Fugue224("Fugue-224", 28),
    Fugue256("Fugue-256", 32),
    Fugue384("Fugue-384", 48),
    Fugue512("Fugue-512", 64),

    Groestl224("Groestl-224", 64),
    Groestl256("Groestl-256", 64),
    Groestl384("Groestl-384", 128),
    Groestl512("Groestl-512", 128),

    Hamsi224("Hamsi-224", 32),
    Hamsi256("Hamsi-256", 32),
    Hamsi384("Hamsi-384", 32),
    Hamsi512("Hamsi-512", 32),

    Luffa224("Luffa-224", 32),
    Luffa256("Luffa-256", 32),
    Luffa384("Luffa-384", 32),
    Luffa512("Luffa-512", 32),

    SHAvite224("SHAvite-224", 64),
    SHAvite256("SHAvite-256", 64),
    SHAvite384("SHAvite-384", 128),
    SHAvite512("SHAvite-512", 128),

    SIMD224("SIMD-224", 64),
    SIMD256("SIMD-256", 64),
    SIMD384("SIMD-384", 128),
    SIMD512("SIMD-512", 128),

    RipeMD("RipeMD", 64),
    RipeMD128("RipeMD128", 64),
    RipeMD160("RipeMD160", 64),
    RipeMD256("RipeMD256", 64),
    RipeMD320("RipeMD320", 64),

    Tiger("Tiger", 64),
    Tiger2("Tiger2", 64),

    Adler32("Adler32", 32),
    CRC32("CRC32", 32),

    GOST3411_2012_256("GOST3411-2012-256", 64),
    GOST3411_2012_512("GOST3411-2012-512", 64),

    Whirlpool("Whirlpool", 64),
    Whirlpool0("Whirlpool-0", 64),
    WhirlpoolT("Whirlpool-T", 64)
}
