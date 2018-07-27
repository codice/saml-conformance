/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
// Build file
group = "org.codice.samlconf.plugins"
description = "API for Plugins users need to implement."

plugins {
    `maven-publish`
}

dependencies {
    compile (project(":library"))
    compile (Libs.restAssured)
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
