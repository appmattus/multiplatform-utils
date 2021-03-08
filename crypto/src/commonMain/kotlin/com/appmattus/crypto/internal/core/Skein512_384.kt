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

package com.appmattus.crypto.internal.core

import com.appmattus.crypto.Algorithm

/**
 * This class implements the Skein-512-384 digest algorithm
 */
@Suppress("ClassName", "MagicNumber")
internal class Skein512_384 : SkeinBouncycastleCore<Skein512_384>(512, 384) {

    override val blockLength: Int
        get() = Algorithm.Skein512_384.blockLength

    override fun toString() = Algorithm.Skein512_384.algorithmName

    override fun dup() = Skein512_384()
}
