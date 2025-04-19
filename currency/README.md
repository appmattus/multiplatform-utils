# currency

A Kotlin Multiplatform Mobile library to format currency values.

## Getting started

![badge][badge-android]
![badge][badge-ios]
![badge][badge-js]
[![Maven Central](https://img.shields.io/maven-central/v/com.appmattus.mpu/currency)](https://search.maven.org/search?q=g:com.appmattus.mpu)

Include the following dependency in your *build.gradle.kts* file:

```kotlin
commonMain {
    implementation("com.appmattus.mpu:currency:<latest-version>")
}
```

Format a currency value: 

```kotlin
Currency.format(value = 1345.23, currencyCode = "GBP", locale = "en-GB")
```

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
