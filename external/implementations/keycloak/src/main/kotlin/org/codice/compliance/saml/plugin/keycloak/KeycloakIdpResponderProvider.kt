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
package org.codice.compliance.saml.plugin.keycloak

import com.jayway.restassured.response.Response
import org.codice.compliance.saml.plugin.IdpPostResponse
import org.codice.compliance.saml.plugin.IdpRedirectResponse
import org.codice.compliance.saml.plugin.IdpResponder
import org.kohsuke.MetaInfServices

@MetaInfServices
class KeycloakIdpResponderProvider : IdpResponder {

    override fun getIdpRedirectResponse(originalResponse: Response): IdpRedirectResponse {
        throw NotImplementedError()
    }

    override fun getIdpPostResponse(originalResponse: Response): IdpPostResponse {
        throw NotImplementedError()
    }
}
