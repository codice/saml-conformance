/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
// Build file
import io.gitlab.arturbosch.detekt.extensions.DetektExtension
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

description = "SAML Conformance Test Kit"

buildscript {
    repositories {
        jcenter()
        mavenCentral()
    }

    dependencies {
        classpath(Libs.kotlinGradlePlugin)
        classpath(Libs.gradleDockerPlugin)
    }
}

plugins {
    id("org.jetbrains.kotlin.jvm").version(Versions.kotlin)
    id("io.gitlab.arturbosch.detekt").version(Versions.detekt)
    id("com.diffplug.gradle.spotless").version(Versions.spotless)
    id("net.ltgt.errorprone").version(Versions.errorprone)
    id("com.adarshr.test-logger").version(Versions.testLogger)
}

allprojects {
    group = "org.codice.samlconf"
    version = Versions.project

    apply(plugin = "com.diffplug.gradle.spotless")

    spotless {
        val kotlinLicenseFile = "codice.license.kt"
        java {
            licenseHeaderFile(rootProject.file(kotlinLicenseFile))
            trimTrailingWhitespace()
            googleJavaFormat()
        }
        kotlin {
            ktlint()
            licenseHeaderFile(rootProject.file(kotlinLicenseFile),
                    "(package|@file|// Default package)")
            trimTrailingWhitespace()
            endWithNewline()
        }
        kotlinGradle {
            ktlint()
            licenseHeaderFile(rootProject.file(kotlinLicenseFile), "// Build file")
            trimTrailingWhitespace()
            endWithNewline()
        }
    }
}

subprojects {
    apply(plugin = "java")
    apply(plugin = "maven")
    apply(plugin = "kotlin-kapt")
    apply(plugin = "kotlin")
    apply(plugin = "com.bmuschko.docker-remote-api")
    apply(plugin = "net.ltgt.errorprone")
    apply(plugin = "com.adarshr.test-logger")

    val sourceCompatibility = Versions.javaTarget
    val targetCompatibility = Versions.javaTarget

    repositories {
        mavenLocal()
        mavenCentral()
        maven { url = uri("http://artifacts.codice.org/content/repositories/thirdparty/") }
    }

    dependencies {
        compile("org.jetbrains.kotlin:kotlin-reflect")
        compile(Libs.kotlinStdlibJdk8)
        compile(Libs.kotlinTest)
        compile(Libs.restAssured)
        compile(Libs.slf4j)
        compile(Libs.staticLog)
        compile(Libs.guava)
        compile(Libs.kotlinTestRunner)
        compile(Libs.junitPlatformSuite)
        compile(Libs.junitPlatformRunner)
        testCompile(Libs.mockk)
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }
}

tasks {
    "build" {
        dependsOn("detektCheck")
    }
}

configure<DetektExtension> {
    defaultProfile(Action {
        input = rootProject.projectDir.absolutePath
        config = "$projectDir/detekt.yml"
        filters = ".*/resources/.*,.*/tmp/.*"
    })
}

val compileKotlin: KotlinCompile by tasks
compileKotlin.kotlinOptions {
    jvmTarget = Versions.javaTarget
}
val compileTestKotlin: KotlinCompile by tasks
compileTestKotlin.kotlinOptions {
    jvmTarget = Versions.javaTarget
}
val compileJava: JavaCompile by tasks
compileJava.options.encoding = "UTF-8"
