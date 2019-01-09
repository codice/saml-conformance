/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
// Build file
group = "org.codice.samlconf.implementations"
description = "implementation for OpenAM IdP"

dependencies {

    compile(Libs.gson)
    compile(Libs.kaptMetainfService)
    compile(Libs.cxfSsoSaml)

    compile(project(":ctk:common"))
    compile(project(":external:samlconf-plugins-api"))

    kapt(Libs.kaptMetainfService)
}
