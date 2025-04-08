# multiplatform-utils

[![CI status](https://github.com/appmattus/multiplatform-utils/workflows/Build/badge.svg)](https://github.com/appmattus/multiplatform-utils/actions)
[![codecov](https://codecov.io/gh/appmattus/multiplatform-utils/branch/main/graph/badge.svg)](https://codecov.io/gh/appmattus/multiplatform-utils)
[![Maven Central](https://img.shields.io/maven-central/v/com.appmattus.mpu/battery)](https://search.maven.org/search?q=g:com.appmattus.mpu)

A collection of Kotlin Multiplatform Mobile libraries to aid in mobile app
development.

[battery](battery/README.md): Access various information about the battery of
the device the app is running on.  
![badge][badge-android]
![badge][badge-ios]

[cryptohash](https://github.com/appmattus/crypto/tree/main/cryptohash/): A set
of cryptographic (and not so cryptographic) hashing functions.  
![badge][badge-android]
![badge][badge-ios]
![badge][badge-jvm]

[connectivity](connectivity/README.md): Discover network connectivity and
distinguish between cellular vs WiFi connection.  
![badge][badge-android]
![badge][badge-ios]

[ignore-test](ignore-test/README.md): Annotations to ignore tests from
specific platforms.  
![badge][badge-android]
![badge][badge-ios]
![badge][badge-jvm]

[package-info](package-info/README.md): An API for querying information about
an application package.  
![badge][badge-android]
![badge][badge-ios]

## Contributing

Please fork this repository and contribute back using [pull requests](https://github.com/appmattus/multiplatform-utils/pulls).

All contributions, large or small, major features, bug fixes, additional
language translations, unit/integration tests are welcomed.

## License

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

Copyright 2021 Appmattus Limited

Licensed under the Apache License, Version 2.0 (the "License"); you may not use
this file except in compliance with the License. You may obtain a copy of the
License at [http://www.apache.org/licenses/LICENSE-2.0](http://www.apache.org/licenses/LICENSE-2.0)

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.

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
