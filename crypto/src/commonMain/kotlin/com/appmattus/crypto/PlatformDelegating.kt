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

abstract class PlatformDelegating<D : PlatformDelegating<D>>(
    algorithm: Algorithm,
    coreImplementation: () -> Digest<*>
) : Digest<D> {

    protected abstract fun dup(): D

    private var delegate = try {
        PlatformDigest().createDigest(algorithm) ?: coreImplementation()
    } catch (expected: Exception) {
        coreImplementation()
    }

    override fun update(input: Byte) = delegate.update(input)

    override fun update(input: ByteArray) = delegate.update(input)

    override fun update(input: ByteArray, offset: Int, length: Int) = delegate.update(input, offset, length)

    override fun digest() = delegate.digest()

    override fun digest(input: ByteArray) = delegate.digest(input)

    override fun digest(output: ByteArray, offset: Int, length: Int) = delegate.digest(output, offset, length)

    override val digestLength
        get() = delegate.digestLength

    override fun reset() = delegate.reset()

    override fun copy(): D {
        return dup().also { copy ->
            copy.delegate = delegate.copy()
        }
    }

    override val blockLength: Int
        get() = delegate.blockLength

    override fun toString() = delegate.toString()
}
