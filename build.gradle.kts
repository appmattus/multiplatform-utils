/*
 * Copyright 2021-2025 Appmattus Limited
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

import io.gitlab.arturbosch.detekt.Detekt
import java.time.ZonedDateTime

plugins {
    alias(libs.plugins.detektGradlePlugin)
    alias(libs.plugins.markdownlintGradlePlugin)
    alias(libs.plugins.gradleMavenPublishPlugin) apply false
    alias(libs.plugins.dokkaPlugin)
}

buildscript {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
    }
    dependencies {
        classpath(libs.buildscript.android)
        classpath(libs.buildscript.kotlin)
        classpath(libs.buildscript.hilt)
        classpath(libs.buildscript.safeargs)
    }
}

apply(from = "$rootDir/gradle/scripts/dependencyUpdates.gradle.kts")

allprojects {
    repositories {
        gradlePluginPortal()
        google()
        mavenCentral()
        maven { url = uri("https://jitpack.io") }
    }
}

dependencies {
    detektPlugins("io.gitlab.arturbosch.detekt:detekt-formatting:${libs.versions.detektGradlePlugin.get()}")
}

tasks.withType<Detekt> {
    jvmTarget = "11"
}

detekt {
    source.setFrom(files(subprojects.map { File(it.projectDir, "src") }))

    buildUponDefaultConfig = true

    autoCorrect = true

    config.setFrom(files("detekt-config.yml"))
}

tasks.maybeCreate("check").dependsOn(tasks.named("detekt"))

tasks.maybeCreate("check").dependsOn(tasks.named("markdownlint"))

allprojects {
    version = System.getenv("GITHUB_REF")?.substring(10) ?: System.getProperty("GITHUB_REF")?.substring(10) ?: "unknown"

    plugins.withType<org.jetbrains.dokka.gradle.DokkaPlugin> {
        dokka {
            dokkaSourceSets {
                configureEach {
                    sourceLink {
                        localDirectory.set(rootDir)
                        remoteUrl("https://github.com/appmattus/multiplatform-utils/blob/main")
                        remoteLineSuffix.set("#L")
                    }
                }
            }

            pluginsConfiguration.html {
                footerMessage.set(
                    provider {
                        "Copyright © 2021-${ZonedDateTime.now().year} Appmattus Limited"
                    }
                )
            }
        }
    }
}
