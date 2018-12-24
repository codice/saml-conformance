/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
// Build file
plugins {
    id("maven-publish")
    id("application")
    id("publishing")
}

description = "Script and CLI to run the tests."

group = "org.codice.samlconf.deployment"

configure<ApplicationPluginConvention> {
    applicationName = "samlconf"
    mainClassName = "org.codice.ctk.CommandKt"

    applicationDefaultJvmArgs = listOf("-Dapp.home=SAMLCTK_APP_HOME")

    applicationDistribution.from("src/main/resources/") {
        into("conf")
    }

    // Copy implementation examples into the distribution
    project(":external:implementations").subprojects.forEach { subProject ->
        applicationDistribution
                .into("implementations/" +
                        subProject.name.replace("samlconf-", "")
                                .replace("-impl", "")) {
                    from(subProject.file("build/resources/main"))
                    from(subProject.file("build/libs"))
                }
    }
}

dependencies {
    compile(project(":external:implementations:samlconf-ddf-impl"))
    compile(project(":external:implementations:samlconf-keycloak-impl"))
    compile(project(":external:implementations:samlconf-openam-impl"))
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
        classpath = files(System.getProperty("app.home") + "/lib/*")
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

artifacts {
    add("archives", tasks.getByPath("distZip"))
}

publishing {
    val releaseUrl = "http://artifacts.codice.org/content/repositories/releases/"
    val snapshotUrl = "http://artifacts.codice.org/content/repositories/snapshots/"
    repositories {
        maven {
            credentials {
                // This will evaluate to an empty string if the property is not present
                // (can be passed in via cli `-P` arg or via `~/.gradle/gradle.properties`
                username = if (project.hasProperty("codice_deploy_username")) {
                    project.property("codice_deploy_username") as String
                } else {
                    ""
                }

                // This will evaluate to an empty string if the property is not present
                // (can be passed in via cli `-P` arg or via `~/.gradle/gradle.properties`
                password = if (project.hasProperty("codice_deploy_password")) {
                    project.property("codice_deploy_password") as String
                } else {
                    ""
                }
            }
            url = if (version.toString().endsWith("SNAPSHOT")) {
                uri(snapshotUrl)
            } else {
                uri(releaseUrl)
            }
        }
    }
    (publications) {
        "mavenJava"(MavenPublication::class) {
            from(components["java"])
            artifact(tasks.getByPath("distZip"))
            pom {
                groupId = "org.codice.samlconf"
                artifactId = "samlconf"
                name.set("SAML Conformance Test Kit")
                description.set("""A set of blackbox tests that verify the conformance of an
                    Identity Provider (IdP) to the SAML V2.0 Standard Specification.""")
                url.set("https://github.com/codice/saml-conformance")
                licenses {
                    license {
                        name.set("The MIT License")
                        url.set("http://www.opensource.org/licenses/mit-license.php")
                    }
                }
                scm {
                    url.set("https://github.com/codice/saml-conformance")
                    connection.set("scm:git:https://github.com/codice/saml-conformance.git")
                    developerConnection
                            .set("scm:git:git://github.com/codice/saml-conformance.git")
                }
            }
        }
    }
}
