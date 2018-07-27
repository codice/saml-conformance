/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
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
