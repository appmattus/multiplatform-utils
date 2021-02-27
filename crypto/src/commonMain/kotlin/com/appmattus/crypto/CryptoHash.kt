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

@file:Suppress("unused", "FunctionName", "SpellCheckingInspection")

package com.appmattus.crypto

import fr.cryptohash.BLAKE224
import fr.cryptohash.BLAKE256
import fr.cryptohash.BLAKE384
import fr.cryptohash.BLAKE512
import fr.cryptohash.BMW224
import fr.cryptohash.BMW256
import fr.cryptohash.BMW384
import fr.cryptohash.BMW512
import fr.cryptohash.CubeHash224
import fr.cryptohash.CubeHash256
import fr.cryptohash.CubeHash384
import fr.cryptohash.CubeHash512
import fr.cryptohash.ECHO224
import fr.cryptohash.ECHO256
import fr.cryptohash.ECHO384
import fr.cryptohash.ECHO512
import fr.cryptohash.Fugue224
import fr.cryptohash.Fugue256
import fr.cryptohash.Fugue384
import fr.cryptohash.Fugue512
import fr.cryptohash.Groestl224
import fr.cryptohash.Groestl256
import fr.cryptohash.Groestl384
import fr.cryptohash.Groestl512
import fr.cryptohash.HAVAL128_3
import fr.cryptohash.HAVAL128_4
import fr.cryptohash.HAVAL128_5
import fr.cryptohash.HAVAL160_3
import fr.cryptohash.HAVAL160_4
import fr.cryptohash.HAVAL160_5
import fr.cryptohash.HAVAL192_3
import fr.cryptohash.HAVAL192_4
import fr.cryptohash.HAVAL192_5
import fr.cryptohash.HAVAL224_3
import fr.cryptohash.HAVAL224_4
import fr.cryptohash.HAVAL224_5
import fr.cryptohash.HAVAL256_3
import fr.cryptohash.HAVAL256_4
import fr.cryptohash.HAVAL256_5
import fr.cryptohash.HMAC
import fr.cryptohash.Hamsi224
import fr.cryptohash.Hamsi256
import fr.cryptohash.Hamsi384
import fr.cryptohash.Hamsi512
import fr.cryptohash.JH224
import fr.cryptohash.JH256
import fr.cryptohash.JH384
import fr.cryptohash.JH512
import fr.cryptohash.Keccak224
import fr.cryptohash.Keccak256
import fr.cryptohash.Keccak384
import fr.cryptohash.Keccak512
import fr.cryptohash.Luffa224
import fr.cryptohash.Luffa256
import fr.cryptohash.Luffa384
import fr.cryptohash.Luffa512
import fr.cryptohash.PANAMA
import fr.cryptohash.RIPEMD
import fr.cryptohash.RIPEMD128
import fr.cryptohash.RIPEMD160
import fr.cryptohash.RadioGatun32
import fr.cryptohash.RadioGatun64
import fr.cryptohash.SHA0
import fr.cryptohash.SHAvite224
import fr.cryptohash.SHAvite256
import fr.cryptohash.SHAvite384
import fr.cryptohash.SHAvite512
import fr.cryptohash.SIMD224
import fr.cryptohash.SIMD256
import fr.cryptohash.SIMD384
import fr.cryptohash.SIMD512
import fr.cryptohash.Shabal192
import fr.cryptohash.Shabal224
import fr.cryptohash.Shabal256
import fr.cryptohash.Shabal384
import fr.cryptohash.Shabal512
import fr.cryptohash.Skein224
import fr.cryptohash.Skein256
import fr.cryptohash.Skein384
import fr.cryptohash.Skein512
import fr.cryptohash.Tiger
import fr.cryptohash.Tiger2
import fr.cryptohash.Whirlpool
import fr.cryptohash.Whirlpool0
import fr.cryptohash.Whirlpool1

fun ByteArray.blake224(): ByteArray = BLAKE224().digest(this)
fun ByteArray.blake256(): ByteArray = BLAKE256().digest(this)
fun ByteArray.blake384(): ByteArray = BLAKE384().digest(this)
fun ByteArray.blake512(): ByteArray = BLAKE512().digest(this)

fun ByteArray.bmw224(): ByteArray = BMW224().digest(this)
fun ByteArray.bmw256(): ByteArray = BMW256().digest(this)
fun ByteArray.bmw384(): ByteArray = BMW384().digest(this)
fun ByteArray.bmw512(): ByteArray = BMW512().digest(this)

fun ByteArray.cubeHash224(): ByteArray = CubeHash224().digest(this)
fun ByteArray.cubeHash256(): ByteArray = CubeHash256().digest(this)
fun ByteArray.cubeHash384(): ByteArray = CubeHash384().digest(this)
fun ByteArray.cubeHash512(): ByteArray = CubeHash512().digest(this)

fun ByteArray.echo224(): ByteArray = ECHO224().digest(this)
fun ByteArray.echo256(): ByteArray = ECHO256().digest(this)
fun ByteArray.echo384(): ByteArray = ECHO384().digest(this)
fun ByteArray.echo512(): ByteArray = ECHO512().digest(this)

fun ByteArray.fugue224(): ByteArray = Fugue224().digest(this)
fun ByteArray.fugue256(): ByteArray = Fugue256().digest(this)
fun ByteArray.fugue384(): ByteArray = Fugue384().digest(this)
fun ByteArray.fugue512(): ByteArray = Fugue512().digest(this)

fun ByteArray.groestl224(): ByteArray = Groestl224().digest(this)
fun ByteArray.groestl256(): ByteArray = Groestl256().digest(this)
fun ByteArray.groestl384(): ByteArray = Groestl384().digest(this)
fun ByteArray.groestl512(): ByteArray = Groestl512().digest(this)

fun ByteArray.hamsi224(): ByteArray = Hamsi224().digest(this)
fun ByteArray.hamsi256(): ByteArray = Hamsi256().digest(this)
fun ByteArray.hamsi384(): ByteArray = Hamsi384().digest(this)
fun ByteArray.hamsi512(): ByteArray = Hamsi512().digest(this)

fun ByteArray.haval128_3(): ByteArray = HAVAL128_3().digest(this)
fun ByteArray.haval128_4(): ByteArray = HAVAL128_4().digest(this)
fun ByteArray.haval128_5(): ByteArray = HAVAL128_5().digest(this)

fun ByteArray.haval160_3(): ByteArray = HAVAL160_3().digest(this)
fun ByteArray.haval160_4(): ByteArray = HAVAL160_4().digest(this)
fun ByteArray.haval160_5(): ByteArray = HAVAL160_5().digest(this)

fun ByteArray.haval192_3(): ByteArray = HAVAL192_3().digest(this)
fun ByteArray.haval192_4(): ByteArray = HAVAL192_4().digest(this)
fun ByteArray.haval192_5(): ByteArray = HAVAL192_5().digest(this)

fun ByteArray.haval224_3(): ByteArray = HAVAL224_3().digest(this)
fun ByteArray.haval224_4(): ByteArray = HAVAL224_4().digest(this)
fun ByteArray.haval224_5(): ByteArray = HAVAL224_5().digest(this)

fun ByteArray.haval256_3(): ByteArray = HAVAL256_3().digest(this)
fun ByteArray.haval256_4(): ByteArray = HAVAL256_4().digest(this)
fun ByteArray.haval256_5(): ByteArray = HAVAL256_5().digest(this)

fun ByteArray.hmac(digest: Digest<*>, key: ByteArray): ByteArray = HMAC(digest, key).digest(this)
fun ByteArray.hmac(digest: Digest<*>, key: ByteArray, outputLength: Int): ByteArray = HMAC(digest, key, outputLength).digest(this)

fun ByteArray.jh224(): ByteArray = JH224().digest(this)
fun ByteArray.jh256(): ByteArray = JH256().digest(this)
fun ByteArray.jh384(): ByteArray = JH384().digest(this)
fun ByteArray.jh512(): ByteArray = JH512().digest(this)

fun ByteArray.keccak224(): ByteArray = Keccak224().digest(this)
fun ByteArray.keccak256(): ByteArray = Keccak256().digest(this)
fun ByteArray.keccak384(): ByteArray = Keccak384().digest(this)
fun ByteArray.keccak512(): ByteArray = Keccak512().digest(this)

fun ByteArray.luffa224(): ByteArray = Luffa224().digest(this)
fun ByteArray.luffa256(): ByteArray = Luffa256().digest(this)
fun ByteArray.luffa384(): ByteArray = Luffa384().digest(this)
fun ByteArray.luffa512(): ByteArray = Luffa512().digest(this)

fun ByteArray.md2(): ByteArray = MD2().digest(this)
fun ByteArray.md4(): ByteArray = MD4().digest(this)
fun ByteArray.md5(): ByteArray = MD5().digest(this)

fun ByteArray.panama(): ByteArray = PANAMA().digest(this)

fun ByteArray.radioGatun32(): ByteArray = RadioGatun32().digest(this)
fun ByteArray.radioGatun64(): ByteArray = RadioGatun64().digest(this)

fun ByteArray.ripemd(): ByteArray = RIPEMD().digest(this)
fun ByteArray.ripemd128(): ByteArray = RIPEMD128().digest(this)
fun ByteArray.ripemd160(): ByteArray = RIPEMD160().digest(this)

fun ByteArray.sha0(): ByteArray = SHA0().digest(this)
fun ByteArray.sha1(): ByteArray = SHA1().digest(this)

fun ByteArray.sha224(): ByteArray = SHA224().digest(this)
fun ByteArray.sha256(): ByteArray = SHA256().digest(this)
fun ByteArray.sha384(): ByteArray = SHA384().digest(this)
fun ByteArray.sha512(): ByteArray = SHA512().digest(this)

fun ByteArray.shabal192(): ByteArray = Shabal192().digest(this)
fun ByteArray.shabal224(): ByteArray = Shabal224().digest(this)
fun ByteArray.shabal256(): ByteArray = Shabal256().digest(this)
fun ByteArray.shabal384(): ByteArray = Shabal384().digest(this)
fun ByteArray.shabal512(): ByteArray = Shabal512().digest(this)

fun ByteArray.shavite224(): ByteArray = SHAvite224().digest(this)
fun ByteArray.shavite256(): ByteArray = SHAvite256().digest(this)
fun ByteArray.shavite384(): ByteArray = SHAvite384().digest(this)
fun ByteArray.shavite512(): ByteArray = SHAvite512().digest(this)

fun ByteArray.simd224(): ByteArray = SIMD224().digest(this)
fun ByteArray.simd256(): ByteArray = SIMD256().digest(this)
fun ByteArray.simd384(): ByteArray = SIMD384().digest(this)
fun ByteArray.simd512(): ByteArray = SIMD512().digest(this)

fun ByteArray.skein224(): ByteArray = Skein224().digest(this)
fun ByteArray.skein256(): ByteArray = Skein256().digest(this)
fun ByteArray.skein384(): ByteArray = Skein384().digest(this)
fun ByteArray.skein512(): ByteArray = Skein512().digest(this)

fun ByteArray.tiger(): ByteArray = Tiger().digest(this)
fun ByteArray.tiger2(): ByteArray = Tiger2().digest(this)

fun ByteArray.whirlpool(): ByteArray = Whirlpool().digest(this)
fun ByteArray.whirlpool0(): ByteArray = Whirlpool0().digest(this)
fun ByteArray.whirlpool1(): ByteArray = Whirlpool1().digest(this)
