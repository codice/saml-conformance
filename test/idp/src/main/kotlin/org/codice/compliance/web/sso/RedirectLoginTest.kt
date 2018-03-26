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

import com.jayway.restassured.RestAssured
import com.jayway.restassured.RestAssured.given
import de.jupf.staticlog.Log
import io.kotlintest.specs.StringSpec
import org.apache.cxf.rs.security.saml.sso.SSOConstants.RELAY_STATE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIG_ALG
import org.codice.compliance.Common
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.prettyPrintXml
import org.codice.compliance.saml.plugin.IdpResponder
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.ID
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.compliance.utils.TestCommon.Companion.authnRequestToString
import org.codice.compliance.utils.TestCommon.Companion.getServiceProvider
import org.codice.compliance.utils.decorators.bindingVerifier
import org.codice.compliance.utils.decorators.decorate
import org.codice.compliance.verification.core.ResponseProtocolVerifier
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT
import org.codice.security.saml.SamlProtocol.REDIRECT_BINDING
import org.codice.security.sign.Encoder
import org.codice.security.sign.SimpleSign
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder

class RedirectLoginTest : StringSpec() {
    companion object {
        /** Sets up positive path tests.
         * @return A string representation of a valid encoded Redirect AuthnRequest.
         */
        private fun createValidAuthnRequest(): String {
            val authnRequest = AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply {
                    value = TestCommon.SP_ISSUER
                }
                assertionConsumerServiceURL = acsUrl[HTTP_REDIRECT]
                id = TestCommon.ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = Common.getSingleSignOnLocation(REDIRECT_BINDING)
                protocolBinding = REDIRECT_BINDING
                isForceAuthn = false
                setIsPassive(true)
            }

            val authnRequestString = authnRequestToString(authnRequest)
            Log.debugWithSupplier { authnRequestString.prettyPrintXml() }
            return Encoder.encodeRedirectMessage(authnRequestString)
        }
    }

    init {
        RestAssured.useRelaxedHTTPSValidation()

        "Redirect AuthnRequest Test" {
            Log.debugWithSupplier { "Redirect AuthnRequest Test" }
            val queryParams = SimpleSign()
                    .signUriString(SAML_REQUEST, createValidAuthnRequest(), null)

            // Get response from AuthnRequest
            val response = given()
                    .urlEncodingEnabled(false)
                    .param(SAML_REQUEST, queryParams[SAML_REQUEST])
                    .param(SIG_ALG, queryParams[SIG_ALG])
                    .param(SIGNATURE, queryParams[SIGNATURE])
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .get(Common.getSingleSignOnLocation(REDIRECT_BINDING))

            // Get response from plugin portion
            val idpResponse = getServiceProvider(IdpResponder::class)
                    .getIdpRedirectResponse(response).decorate()
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom
            ResponseProtocolVerifier(responseDom, ID, acsUrl[HTTP_REDIRECT]).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_REDIRECT]).verify()
        }

        "Redirect AuthnRequest With Relay State Test" {
            Log.debugWithSupplier { "Redirect AuthnRequest With Relay State Test" }
            val queryParams = SimpleSign()
                    .signUriString(SAML_REQUEST, createValidAuthnRequest(), EXAMPLE_RELAY_STATE)

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
                    .get(Common.getSingleSignOnLocation(REDIRECT_BINDING))

            // Get response from plugin portion
            val idpResponse = getServiceProvider(IdpResponder::class)
                    .getIdpRedirectResponse(response).decorate().apply {
                        isRelayStateGiven = true
                    }

            val bindingVerifier = idpResponse.bindingVerifier()
            bindingVerifier.verify()

            val responseDom = idpResponse.responseDom
            ResponseProtocolVerifier(responseDom, TestCommon.ID, acsUrl[HTTP_REDIRECT]).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_REDIRECT]).verify()
        }

        "Redirect AuthnRequest Without ACS Url Test" {
            Log.debugWithSupplier { "Redirect AuthnRequest Without ACS Url Test" }
            val authnRequest = AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply {
                    value = TestCommon.SP_ISSUER
                }
                id = TestCommon.ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = Common.getSingleSignOnLocation(REDIRECT_BINDING)
                protocolBinding = REDIRECT_BINDING
                isForceAuthn = false
                setIsPassive(true)
            }

            val authnRequestString = authnRequestToString(authnRequest)
            Log.debugWithSupplier { authnRequestString.prettyPrintXml() }

            val encodedRequest = Encoder.encodeRedirectMessage(authnRequestString)
            val queryParams = SimpleSign().signUriString(SAML_REQUEST, encodedRequest, null)

            // Get response from AuthnRequest
            val response = given()
                    .urlEncodingEnabled(false)
                    .param(SAML_REQUEST, queryParams[SAML_REQUEST])
                    .param(SIG_ALG, queryParams[SIG_ALG])
                    .param(SIGNATURE, queryParams[SIGNATURE])
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .get(Common.getSingleSignOnLocation(REDIRECT_BINDING))

            // Get response from plugin portion
            val idpResponse = getServiceProvider(IdpResponder::class)
                    .getIdpRedirectResponse(response).decorate()
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom
            ResponseProtocolVerifier(responseDom, TestCommon.ID, acsUrl[HTTP_REDIRECT]).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_REDIRECT]).verify()
        }
    }
}
