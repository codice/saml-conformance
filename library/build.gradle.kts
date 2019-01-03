/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
// Build file
description = "Common libraries from DDF for building request/response, signing and parsing."

plugins {
    `maven-publish`
}

dependencies {
    compile(Libs.cxfSsoSaml)
    compile(Libs.googleHttpClient)
    compile(Libs.keyczar)
    compile(Libs.jtidy)
    compile(Libs.jansi)

    testImplementation(Libs.junitJupiter)
    testRuntimeOnly(Libs.junitJupiterEngine)
}

publishing {
    (publications) {
        "mavenJava"(MavenPublication::class) {
            from(components["java"])
        }
    }
}

tasks {
    "build" {
        dependsOn("publishToMavenLocal")
    }
}
