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
apply(plugin = "application")

description = "Script and CLI to run the tests."

group = "org.codice.samlconf.deployment"

configure<ApplicationPluginConvention> {
    applicationName = "samlconf"
    mainClassName = "org.codice.ctk.CommandKt"

    applicationDefaultJvmArgs = listOf("-Dapp.home=SAMLCTK_APP_HOME")

    applicationDistribution.from("src/main/resources/") {
        into( "conf")
    }

    // Copy implementation examples into the distribution
    project(":external:implementations").getSubprojects().forEach { subProject ->
        applicationDistribution
                .into("implementations/" +
                        subProject.name.replace("samlconf-", "")
                                .replace("-impl", "")) {
            from (subProject.file("build/resources/main"))
            from (subProject.file("build/libs"))
        }
    }
}

dependencies {
    compile(project(":external:implementations:samlconf-ddf-impl"))
    compile(project(":external:implementations:samlconf-keycloak-impl"))
    compile(project(":library"))
    compile(project(":external:samlconf-plugins-api"))
    compile(project(":ctk:common"))
    compile(project(":ctk:idp"))

    compile(Libs.kopperTyped)
    compile(Libs.jansi)
}

// We don"t want to include the implementation jars in the classpath
// since they"re loaded from a specific directory.
tasks {
    "copyToLib"(Copy::class) {
        from(configurations.runtime.exclude(group = "org.codice.samlconf.implementations"))
        into("build")
    }

    "startScripts"(CreateStartScripts::class) {
        doLast {
            unixScript.let {
                it.writeText(it.readText().replace("SAMLCTK_APP_HOME", "\$APP_HOME"))
            }
            windowsScript.let {
                it.writeText(it.readText().replace("SAMLCTK_APP_HOME", "%~dp0.."))
            }
        }
    }

    "build" {
        finalizedBy("installDist")
    }
}
