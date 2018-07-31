/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
// Build file
rootProject.name = "saml-conformance"

include("library",
        "external:samlconf-plugins-api",
        "external:implementations:samlconf-ddf-impl",
        "external:implementations:samlconf-keycloak-impl",
        "ctk:common",
        "ctk:idp",
        "deployment:distribution",
        "deployment:docker")
