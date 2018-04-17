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
import com.jayway.restassured.response.Response
import de.jupf.staticlog.Log
import io.kotlintest.specs.StringSpec
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.codice.compliance.Common.Companion.getSingleSignOnLocation
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.saml.plugin.IdpSSOResponder
import org.codice.compliance.utils.TestCommon.Companion.AUTHN_REQUEST
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.ID
import org.codice.compliance.utils.TestCommon.Companion.SP_ISSUER
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.compliance.utils.TestCommon.Companion.authnRequestToString
import org.codice.compliance.utils.TestCommon.Companion.getServiceProvider
import org.codice.compliance.utils.decorate
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.core.responses.AuthnRequestProtocolResponseVerifier
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.saml.SamlProtocol.REDIRECT_BINDING
import org.codice.security.sign.Encoder
import org.codice.security.sign.SimpleSign
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder

class RedirectSSOTest : StringSpec() {
    companion object {
        /**
         * Provides a default request for testing
         * @return A valid Redirect AuthnRequest.
         */
        private fun createDefaultAuthnRequest(): AuthnRequest {
            return AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply {
                    value = SP_ISSUER
                }
                assertionConsumerServiceURL = acsUrl[HTTP_POST]
                id = ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = getSingleSignOnLocation(REDIRECT_BINDING)
                protocolBinding = REDIRECT_BINDING
                isForceAuthn = false
                setIsPassive(false)
            }
        }

        /**
         * Encodes an AuthnRequest
         * @return A string representation of the encoded input request
         */
        private fun encodeAuthnRequest(authnRequest: AuthnRequest): String {
            val authnRequestString = authnRequestToString(authnRequest)
            authnRequestString.debugPrettyPrintXml(AUTHN_REQUEST)
            return Encoder.encodeRedirectMessage(authnRequestString)
        }

        /**
         * Submits a request to the IdP with the given parameters.
         * @return The IdP response
         */
        private fun sendAuthnRequest(queryParams: Map<String, String>): Response {
            return given()
                    .urlEncodingEnabled(false)
                    .params(queryParams)
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .get(getSingleSignOnLocation(REDIRECT_BINDING))
        }
    }

    init {
        RestAssured.useRelaxedHTTPSValidation()

        "Redirect AuthnRequest Test" {
            Log.debugWithSupplier { "Redirect AuthnRequest Test" }
            val authnRequest = createDefaultAuthnRequest()
            val encodedRequest = encodeAuthnRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)

            val response = sendAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            // Get response from plugin portion
            val idpResponse = getServiceProvider(IdpSSOResponder::class)
                    .getRedirectResponse(response).decorate()
            // TODO When DDF is fixed to return a POST SSO response, uncomment this line
            // SingleSignOnProfileVerifier.verifyBinding(idpResponse)
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom
            AuthnRequestProtocolResponseVerifier(responseDom, ID, acsUrl[HTTP_POST]).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
        }

        "Redirect AuthnRequest With Relay State Test" {
            Log.debugWithSupplier { "Redirect AuthnRequest With Relay State Test" }
            val authnRequest = createDefaultAuthnRequest()
            val encodedRequest = encodeAuthnRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST, encodedRequest,
                    EXAMPLE_RELAY_STATE)

            // Get response from AuthnRequest
            val response = sendAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = getServiceProvider(IdpSSOResponder::class)
                    .getRedirectResponse(response).decorate().apply {
                        isRelayStateGiven = true
                    }
            // TODO When DDF is fixed to return a POST SSO response, uncomment this line
            // SingleSignOnProfileVerifier.verifyBinding(idpResponse)
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom
            AuthnRequestProtocolResponseVerifier(responseDom, ID, acsUrl[HTTP_POST])
                    .verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
        }

        "Redirect AuthnRequest Without ACS Url Test" {
            Log.debugWithSupplier { "Redirect AuthnRequest Without ACS Url Test" }
            val authnRequest = createDefaultAuthnRequest().apply {
                assertionConsumerServiceURL = null
            }

            val encodedRequest = encodeAuthnRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)

            // Get response from AuthnRequest
            val response = sendAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            // Get response from plugin portion
            val idpResponse = getServiceProvider(IdpSSOResponder::class)
                    .getRedirectResponse(response).decorate()
            // TODO When DDF is fixed to return a POST SSO response, uncomment this line
            // SingleSignOnProfileVerifier.verifyBinding(idpResponse)
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom
            AuthnRequestProtocolResponseVerifier(responseDom, ID, acsUrl[HTTP_POST])
                    .verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
        }
    }
}
