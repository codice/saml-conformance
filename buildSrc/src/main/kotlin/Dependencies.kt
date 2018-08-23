/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
//  Default package
@file:Suppress("MaxLineLength")
object Versions {
    const val project = "1.1-SNAPSHOT"

    const val javaTarget = "1.8"

    const val kotlin = "1.2.61"
    const val gradleDocker = "3.2.4"
    const val kotlinTest = "3.1.9"
    const val restAssured = "3.1.1"
    const val slf4j = "1.7.25"
    const val guava = "26.0-jre"
    const val spotless = "3.14.0"
    const val errorprone = "0.0.16"
    const val googleErrorProne = "2.3.1"
    const val testLogger = "1.4.0"
    const val detekt = "1.0.0.RC8"
    const val staticLog = "2.2.0"
    const val mockk = "1.8.6"
    const val junitJupiter = "5.2.0"
    const val junitPlatform = "1.2.0"
    const val wss4j = "2.2.2"
    const val cxf = "3.2.4"
    const val kaptMetainf = "1.8"
    const val gson = "2.8.5"
    const val kopperTyped = "0.0.3"
    const val jansi = "1.17.1"
    const val googleHttpClient = "1.24.1"
    const val keyczar = "0.66"
    const val jtidy = "r938"
}

object Libs {
    const val kotlinGradlePlugin = "org.jetbrains.kotlin:kotlin-gradle-plugin:${Versions.kotlin}"
    const val kotlinStdlibJdk8 = "org.jetbrains.kotlin:kotlin-stdlib-jdk8:${Versions.kotlin}"
    const val kotlinTest = "org.jetbrains.kotlin:kotlin-test:${Versions.kotlin}"

    const val googleErrorProne = "com.google.errorprone:error_prone_core:${Versions.googleErrorProne}"
    const val gradleDockerPlugin = "com.bmuschko:gradle-docker-plugin:${Versions.gradleDocker}"
    const val restAssured = "io.rest-assured:rest-assured:${Versions.restAssured}"
    const val slf4j = "org.slf4j:slf4j-api:${Versions.slf4j}"
    const val staticLog = "io.github.jupf.staticlog:staticlog:${Versions.staticLog}"
    const val guava = "com.google.guava:guava:${Versions.guava}"
    const val kotlinTestRunner = "io.kotlintest:kotlintest-runner-junit5:${Versions.kotlinTest}"

    const val junitPlatformSuite = "org.junit.platform:junit-platform-suite-api:${Versions.junitPlatform}"
    const val junitPlatformRunner = "org.junit.platform:junit-platform-runner:${Versions.junitPlatform}"
    const val junitJupiter = "org.junit.jupiter:junit-jupiter-api:${Versions.junitJupiter}"
    const val junitJupiterEngine = "org.junit.jupiter:junit-jupiter-engine:${Versions.junitJupiter}"
    const val junitJupiterParams = "org.junit.jupiter:junit-jupiter-params:${Versions.junitJupiter}"
    const val mockk = "io.mockk:mockk:${Versions.mockk}"

    const val cxfSsoSaml = "org.apache.cxf:cxf-rt-rs-security-sso-saml:${Versions.cxf}"
    const val wss4jCommon = "org.apache.wss4j:wss4j-ws-security-common:${Versions.wss4j}"

    const val kaptMetainfService = "org.kohsuke.metainf-services:metainf-services:${Versions.kaptMetainf}"
    const val gson = "com.google.code.gson:gson:${Versions.gson}"

    const val kopperTyped = "us.jimschubert:kopper-typed:${Versions.kopperTyped}"
    const val jansi = "org.fusesource.jansi:jansi:${Versions.jansi}"
    const val googleHttpClient = "com.google.http-client:google-http-client:${Versions.googleHttpClient}"
    const val keyczar = "org.keyczar:keyczar:${Versions.keyczar}"
    const val jtidy = "net.sf.jtidy:jtidy:${Versions.jtidy}"
}
