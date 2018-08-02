/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
// Build file
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

    repositories {
        mavenLocal()
        mavenCentral()
        maven { url = uri("http://artifacts.codice.org/content/repositories/thirdparty/") }
    }

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
    apply(plugin = "kotlin")
    apply(plugin = "kotlin-kapt")
    apply(plugin = "com.bmuschko.docker-remote-api")
    apply(plugin = "net.ltgt.errorprone")
    apply(plugin = "com.adarshr.test-logger")

    val sourceCompatibility = Versions.javaTarget
    val targetCompatibility = Versions.javaTarget

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
        errorprone(Libs.googleErrorProne)
    }

    tasks.withType<Test> {
        useJUnitPlatform()
    }
}

tasks {
    "check" {
        dependsOn("detektCheck")
    }
}

detekt {
    version = Versions.detekt

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
