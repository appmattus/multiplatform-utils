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
import com.appmattus.crypto.internal.core.jvm.Adler32
import com.appmattus.crypto.internal.core.jvm.CRC32
import org.bouncycastle.crypto.digests.Blake2bDigest
import org.bouncycastle.crypto.digests.Blake2sDigest

internal actual class PlatformDigest {

    actual fun create(algorithm: Algorithm): Digest<*>? {
        return when (algorithm) {
            Algorithm.Adler32 -> Adler32()
            Algorithm.CRC32 -> CRC32()

            is Algorithm.Blake2b -> try {
                when (algorithm) {
                    is Algorithm.Blake2b.Keyed -> {
                        val digest = Blake2bDigest(algorithm.key, algorithm.digestLength, algorithm.salt, algorithm.personalisation)
                        ExtendedDigestPlatform(algorithm.algorithmName, digest)
                    }
                    else -> {
                        val digest = Blake2bDigest(algorithm.digestLength shl 3)
                        ExtendedDigestPlatform(algorithm.algorithmName, digest)
                    }
                }
            } catch (expected: Exception) {
                null
            }

            is Algorithm.Blake2s -> try {
                when (algorithm) {
                    is Algorithm.Blake2s.Keyed -> {
                        val digest = Blake2sDigest(algorithm.key, algorithm.digestLength, algorithm.salt, algorithm.personalisation)
                        ExtendedDigestPlatform(algorithm.algorithmName, digest)
                    }
                    else -> {
                        val digest = Blake2sDigest(algorithm.digestLength shl 3)
                        ExtendedDigestPlatform(algorithm.algorithmName, digest)
                    }
                }
            } catch (expected: Exception) {
                null
            }

            else -> try {
                MessageDigestPlatform(algorithm.algorithmName, algorithm.blockLength)
            } catch (expected: Exception) {
                null
            }
        }
    }
}
