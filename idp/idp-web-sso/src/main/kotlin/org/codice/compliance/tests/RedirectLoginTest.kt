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
package org.codice.compliance.tests

import com.google.common.io.Resources.getResource
import com.jayway.restassured.RestAssured
import com.jayway.restassured.RestAssured.given
import io.kotlintest.specs.StringSpec
import org.apache.cxf.rs.security.saml.sso.SSOConstants
import org.apache.cxf.rs.security.saml.sso.SSOConstants.*
import org.codice.compliance.*
import org.codice.compliance.saml.plugin.IdpResponder
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.Encoder
import org.codice.security.sign.SimpleSign
import java.time.Instant

class RedirectLoginTest : StringSpec() {
    companion object {
        fun setupAuthnRequest(relayState: String?): Map<String, String> {
            val baseRequest = getResource("redirect-authn-request.xml").readText()
            val encodedRequest = Encoder.encodeRedirectMessage(String.format(baseRequest, ACS_URL, getSingleSignOnLocation(SamlProtocol.REDIRECT_BINDING), ID, Instant.now().toString(), SP_ISSUER))
            return SimpleSign().signUriString(SAML_REQUEST, encodedRequest, relayState)
        }
    }

    init {
        RestAssured.useRelaxedHTTPSValidation()

        "Redirect AuthnRequest Test" {
            val queryParams = setupAuthnRequest(null)

            // Get response from AuthnRequest
            val response = given()
                    .urlEncodingEnabled(false)
                    .param(SAML_REQUEST, queryParams[SAML_REQUEST])
                    .param(SIG_ALG, queryParams[SIG_ALG])
                    .param(SIGNATURE, queryParams[SIGNATURE])
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .get(getSingleSignOnLocation(SamlProtocol.REDIRECT_BINDING))

            val idpResponse = getServiceProvider(IdpResponder::class.java).getIdpRedirectResponse(response)
            assertResponse(idpResponse, false)
        }

        "Redirect AuthnRequest With Relay State Test" {
            val queryParams = setupAuthnRequest(EXAMPLE_RELAY_STATE)

            // Get response from AuthnRequest
            val response = given()
                    .urlEncodingEnabled(false)
                    .param(SAML_REQUEST, queryParams[SAML_REQUEST])
                    .param(SIG_ALG, queryParams[SIG_ALG])
                    .param(SIGNATURE, queryParams[SIGNATURE])
                    .param(RELAY_STATE, queryParams[RELAY_STATE])
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .get(getSingleSignOnLocation(SamlProtocol.REDIRECT_BINDING))

            val idpResponse = getServiceProvider(IdpResponder::class.java).getIdpRedirectResponse(response)
            assertResponse(idpResponse, true)
        }
    }
}