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

import com.jayway.restassured.RestAssured
import com.jayway.restassured.response.Response
import org.codice.compliance.saml.plugin.IdpSSOResponder
import org.kohsuke.MetaInfServices

@MetaInfServices
class KeycloakIdpSSOResponderProvider : IdpSSOResponder {

    override fun getResponseForRedirectRequest(originalResponse: Response): Response {
        return postUserForm(originalResponse)
    }

    override fun getResponseForPostRequest(originalResponse: Response): Response {
        val loginPageResponse = RestAssured.given()
                .urlEncodingEnabled(false)
                .cookies(originalResponse.cookies)
                .log()
                .ifValidationFails()
                .`when`()
                .get(originalResponse.getHeader("Location"))

        return postUserForm(loginPageResponse, originalResponse.cookies)
    }

    private fun postUserForm(responseWithForm: Response,
                             cookies: Map<String, String> = responseWithForm.cookies): Response {
        val uriString = responseWithForm
                .then()
                .extract()
                .htmlPath()
                .getNode("html.body.**.find { it.name() == 'form' }")
                .getAttribute("action")

        return RestAssured.given()
                .urlEncodingEnabled(false)
                .cookies(cookies)
                .body("username=admin&password=admin")
                .contentType("application/x-www-form-urlencoded")
                .log()
                .ifValidationFails()
                .`when`()
                .post(uriString)
    }
}
