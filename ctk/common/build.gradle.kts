/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
// Build file
group = "org.codice.samlconf.test"
description = "Common Functions for IdP Tests."

dependencies {
    compile(project(":library"))
    compile(project(":external:samlconf-plugins-api"))

    compile(Libs.wss4jCommon)
    testCompile(Libs.kotlinTestRunner)
    testImplementation(Libs.junitJupiter)
    testImplementation(Libs.junitJupiterParams)
    testRuntimeOnly(Libs.junitJupiterEngine)
}
