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
import com.bmuschko.gradle.docker.tasks.image.DockerBuildImage

description = "Dockerized SAML CTK."

dependencies {
    compile(project(":deployment:distribution"))
}

// Copy the distribution from the distribution module over to the build module
tasks {
    "copyDistribution" {
        dependsOn(":deployment:distribution:installDist")
        doLast {
            project.copy {
                val distroProject = project(":deployment:distribution")

                val distroPath = "${distroProject.buildDir}/distributions/" +
                        "samlconf-${Versions.project}.tar"
                from(distroProject.file(distroPath)) {
                    rename("[-]${Versions.project}", "")
                }
                into("build")
            }
        }
    }

    "docker"(DockerBuildImage::class) {
        dependsOn("copyDistribution")
        dockerFile = file("Dockerfile")
        inputDir = file("$projectDir")
        tag = "codice/samlconf:latest"
    }
}
