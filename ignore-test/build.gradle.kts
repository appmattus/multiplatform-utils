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

import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    kotlin("multiplatform")
    id("com.vanniktech.maven.publish")
    id("org.jetbrains.dokka")
}

kotlin {
    jvm("junit4")
    jvm("junit5")
    ios()

    sourceSets {
        val commonMain by getting {
            dependencies {
                implementation(kotlin("test-common"))
                implementation(kotlin("test-annotations-common"))
            }
        }
        val commonTest by getting
        val junit4Main by getting {
            dependencies {
                compileOnly(kotlin("test-junit"))
            }
        }
        val junit4Test by getting
        val junit5Main by getting {
            dependencies {
                compileOnly(kotlin("test-junit5"))
            }
        }
        val junit5Test by getting
        val iosMain by getting
        val iosTest by getting
    }
}

tasks.withType<KotlinCompile> { kotlinOptions.jvmTarget = JavaVersion.VERSION_1_8.toString() }
