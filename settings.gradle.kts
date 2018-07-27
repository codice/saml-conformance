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
rootProject.name = "saml-conformance"

include("library",
        "external:samlconf-plugins-api",
        "external:implementations:samlconf-ddf-impl",
        "external:implementations:samlconf-keycloak-impl",
        "ctk:common",
        "ctk:idp",
        "deployment:distribution",
        "deployment:docker")
