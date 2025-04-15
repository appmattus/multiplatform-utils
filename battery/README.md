# battery

A Kotlin Multiplatform Mobile library to access various information about the
battery of the device the app is running on.

## Getting started

![badge][badge-android]
![badge][badge-ios]
[![Maven Central](https://img.shields.io/maven-central/v/com.appmattus.mpu/battery)](https://search.maven.org/search?q=g:com.appmattus.mpu)

Include the following dependency in your *build.gradle.kts* file:

```kotlin
commonMain {
    implementation("com.appmattus.mpu:battery:<latest-version>")
}
```

Create an instance of Battery

To create a hash first create a digest with `Digest.create` providing the name
of the hash you wish to use, then update with `update` and create the hash with
`digest`:

```kotlin
// Create a digest
val digest = Digest.create(Algorithm.Blake2b_512)

// Update the digest with data and generate the hash
digest.update(byteArray)
val hash: ByteArray = digest.digest()

// Alternatively use the shorthand form to update and generate with one function
digest.digest(byteArray)
```

---

Inspired by the Flutter [battery](https://pub.dev/packages/battery) package.

[badge-android]: http://img.shields.io/badge/platform-android-6EDB8D.svg?style=flat
[badge-ios]: http://img.shields.io/badge/platform-ios-CDCDCD.svg?style=flat
[badge-js]: http://img.shields.io/badge/platform-js-F8DB5D.svg?style=flat
[badge-jvm]: http://img.shields.io/badge/platform-jvm-DB413D.svg?style=flat
[badge-linux]: http://img.shields.io/badge/platform-linux-2D3F6C.svg?style=flat
[badge-windows]: http://img.shields.io/badge/platform-windows-4D76CD.svg?style=flat
[badge-mac]: http://img.shields.io/badge/platform-macos-111111.svg?style=flat
[badge-watchos]: http://img.shields.io/badge/platform-watchos-C0C0C0.svg?style=flat
[badge-tvos]: http://img.shields.io/badge/platform-tvos-808080.svg?style=flat
[badge-wasm]: https://img.shields.io/badge/platform-wasm-624FE8.svg?style=flat
