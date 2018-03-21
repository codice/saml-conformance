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
package org.codice.compliance.web.sso

import com.google.common.io.Resources.getResource
import com.jayway.restassured.RestAssured
import com.jayway.restassured.RestAssured.given
import io.kotlintest.specs.StringSpec
import org.apache.cxf.rs.security.saml.sso.SSOConstants.*
import org.codice.compliance.Common
import org.codice.compliance.saml.plugin.IdpResponder
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.ACS_URL
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.ID
import org.codice.compliance.utils.TestCommon.Companion.SP_ISSUER
import org.codice.compliance.utils.TestCommon.Companion.getServiceProvider
import org.codice.compliance.utils.decorators.bindingVerifier
import org.codice.compliance.utils.decorators.decorate
import org.codice.compliance.verification.core.CoreVerifier
import org.codice.compliance.verification.core.ResponseProtocolVerifier
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.Encoder
import org.codice.security.sign.SimpleSign
import java.time.Instant

class RedirectLoginTest : StringSpec() {
    companion object {
        fun setupAuthnRequest(relayState: String?): Map<String, String> {
            val baseRequest = getResource("redirect-authn-request.xml").readText()
            val encodedRequest = Encoder.encodeRedirectMessage(String.format(baseRequest,
                    ACS_URL,
                    Common.getSingleSignOnLocation(SamlProtocol.REDIRECT_BINDING),
                    ID,
                    Instant.now().toString(),
                    SP_ISSUER))
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
                    .get(Common.getSingleSignOnLocation(SamlProtocol.REDIRECT_BINDING))

            // Get response from plugin portion
            val idpResponse = getServiceProvider(IdpResponder::class)
                    .getIdpRedirectResponse(response).decorate()

            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom

            CoreVerifier(responseDom).verify()

            ResponseProtocolVerifier(responseDom, ID).verify()

            SingleSignOnProfileVerifier(responseDom).verify()
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
                    .get(Common.getSingleSignOnLocation(SamlProtocol.REDIRECT_BINDING))

            // Get response from plugin portion
            val idpResponse = getServiceProvider(IdpResponder::class)
                    .getIdpRedirectResponse(response).decorate().apply {
                        isRelayStateGiven = true
                    }

            val bindingVerifier = idpResponse.bindingVerifier()
            bindingVerifier.verify()

            val responseDom = idpResponse.responseDom

            CoreVerifier(responseDom).verify()

            ResponseProtocolVerifier(responseDom, TestCommon.ID).verify()

            SingleSignOnProfileVerifier(responseDom).verify()
        }
    }
}
