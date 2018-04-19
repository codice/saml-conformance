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
package org.codice.compliance.web.sso.error

import com.jayway.restassured.RestAssured
import com.jayway.restassured.RestAssured.given
import com.jayway.restassured.response.Response
import de.jupf.staticlog.Log
import io.kotlintest.specs.StringSpec
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.codice.compliance.Common.Companion.getSingleSignOnLocation
import org.codice.compliance.SAMLBindings_3_4_3_a1
import org.codice.compliance.SAMLCore_3_2_1_e
import org.codice.compliance.SAMLProfiles_4_1_4_1_a
import org.codice.compliance.SAMLProfiles_4_1_4_1_b
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.utils.TestCommon.Companion.AUTHN_REQUEST
import org.codice.compliance.utils.TestCommon.Companion.ID
import org.codice.compliance.utils.TestCommon.Companion.INCORRECT_ACS_URL
import org.codice.compliance.utils.TestCommon.Companion.INCORRECT_DESTINATION
import org.codice.compliance.utils.TestCommon.Companion.RELAY_STATE_GREATER_THAN_80_BYTES
import org.codice.compliance.utils.TestCommon.Companion.REQUESTER
import org.codice.compliance.utils.TestCommon.Companion.SP_ISSUER
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.compliance.utils.TestCommon.Companion.authnRequestToString
import org.codice.compliance.utils.TestCommon.Companion.parseErrorResponse
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.core.CoreVerifier
import org.codice.compliance.verification.profile.ProfilesVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.saml.SamlProtocol.REDIRECT_BINDING
import org.codice.security.sign.Encoder
import org.codice.security.sign.SimpleSign
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import org.opensaml.saml.saml2.core.impl.SubjectBuilder

class RedirectSSOErrorTest : StringSpec() {
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

        // Negative Path Tests
        "Redirect AuthnRequest With Relay State Greater Than 80 Bytes Test" {
            Log.debugWithSupplier {
                "Redirect AuthnRequest With Relay State Greater Than 80 Bytes Test"
            }
            val authnRequest = createDefaultAuthnRequest()
            val encodedRequest = encodeAuthnRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    RELAY_STATE_GREATER_THAN_80_BYTES)

            // Get response from AuthnRequest
            val response = sendAuthnRequest(queryParams)

            val idpResponse = parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            CoreVerifier.verifyErrorStatusCode(responseDom, samlErrorCode = SAMLBindings_3_4_3_a1,
                    expectedStatusCode = REQUESTER)
        }.config(enabled = false)

        "Redirect Incomplete AuthnRequest In URL Query Test" {
            Log.debugWithSupplier {
                "Redirect Incomplete AuthnRequest In URL Query Test"
            }
            val authnRequest = createDefaultAuthnRequest()
            val encodedRequest = encodeAuthnRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)
            val qpSamlReq = queryParams[SAML_REQUEST]
            queryParams.set(SAML_REQUEST, qpSamlReq?.substring(0, qpSamlReq.length / 2))

            // Get response from AuthnRequest
            val response = sendAuthnRequest(queryParams)

            val idpResponse = parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            CoreVerifier.verifyErrorStatusCode(responseDom, samlErrorCode = SAMLBindings_3_4_3_a1,
                    expectedStatusCode = REQUESTER)
        }.config(enabled = false)

        "Empty Redirect AuthnRequest Test" {
            Log.debugWithSupplier { "Empty Redirect AuthnRequest Test" }
            val authnRequest = AuthnRequestBuilder().buildObject()
            val encodedRequest = encodeAuthnRequest(authnRequest)
            val queryParams = mapOf(SAML_REQUEST to encodedRequest)

            val response = sendAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            CoreVerifier.verifyErrorStatusCode(responseDom, samlErrorCode = SAMLProfiles_4_1_4_1_a,
                    expectedStatusCode = REQUESTER)
            ProfilesVerifier(responseDom).verifyErrorResponseAssertion()
        }.config(enabled = false)

        "Redirect AuthnRequest With Empty Subject Test" {
            Log.debugWithSupplier { "Redirect AuthnRequest With Empty Subject Test" }
            val authnRequest = createDefaultAuthnRequest().apply {
                subject = SubjectBuilder().buildObject()
            }
            val encodedRequest = encodeAuthnRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)

            // Get response from AuthnRequest
            val response = sendAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            CoreVerifier.verifyErrorStatusCode(responseDom, samlErrorCode = SAMLProfiles_4_1_4_1_b,
                    expectedStatusCode = REQUESTER)
            ProfilesVerifier(responseDom).verifyErrorResponseAssertion(SAMLProfiles_4_1_4_1_b)
        }.config(enabled = false)

        "Redirect AuthnRequest With Incorrect ACS URL And Index Test" {
            Log.debugWithSupplier { "Redirect AuthnRequest With Incorrect ACS URL And Index Test" }
            val authnRequest = createDefaultAuthnRequest().apply {
                assertionConsumerServiceURL = INCORRECT_ACS_URL
                assertionConsumerServiceIndex = -1
            }
            val encodedRequest = encodeAuthnRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(SAML_REQUEST, encodedRequest, null)

            // Get response from AuthnRequest
            val response = sendAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            // DDF returns a valid response to the incorrect url
        }.config(enabled = false)

        "Redirect AuthnRequest With Non-Matching Destination" {
            Log.debugWithSupplier { "Redirect AuthnRequest With Non-Matching Destination" }
            val authnRequest = createDefaultAuthnRequest().apply {
                destination = INCORRECT_DESTINATION
            }
            val encodedRequest = encodeAuthnRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(SAML_REQUEST, encodedRequest, null)

            // Get response from AuthnRequest
            val response = sendAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            CoreVerifier.verifyErrorStatusCode(responseDom, samlErrorCode = SAMLCore_3_2_1_e,
                    expectedStatusCode = REQUESTER)
        }.config(enabled = false)
    }
}
