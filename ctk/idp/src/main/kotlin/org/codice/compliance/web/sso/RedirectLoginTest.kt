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
import org.codice.compliance.Common
import org.codice.compliance.SAMLBindings_3_4_3_a1
import org.codice.compliance.SAMLCore_3_2_1_e
import org.codice.compliance.SAMLProfiles_4_1_4_1_a
import org.codice.compliance.SAMLProfiles_4_1_4_1_b
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.prettyPrintXml
import org.codice.compliance.saml.plugin.IdpResponder
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.ID
import org.codice.compliance.utils.TestCommon.Companion.INCORRECT_ACS_URL
import org.codice.compliance.utils.TestCommon.Companion.INCORRECT_DESTINATION
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.compliance.utils.TestCommon.Companion.authnRequestToString
import org.codice.compliance.utils.TestCommon.Companion.getServiceProvider
import org.codice.compliance.utils.decorators.decorate
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.core.CoreVerifier
import org.codice.compliance.verification.core.ResponseProtocolVerifier
import org.codice.compliance.verification.profile.ProfilesVerifier
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT
import org.codice.security.saml.SamlProtocol.REDIRECT_BINDING
import org.codice.security.sign.Encoder
import org.codice.security.sign.SimpleSign
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import org.opensaml.saml.saml2.core.impl.SubjectBuilder

class RedirectLoginTest : StringSpec() {
    companion object {
        /**
         * Provides a default request for testing
         * @return A valid Redirect AuthnRequest.
         */
        private fun createDefaultAuthnRequest(): AuthnRequest {
            return AuthnRequestBuilder().buildObject().apply {
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
                setIsPassive(false)
            }
        }

        /**
         * Encodes an AuthnRequest
         * @return A string representation of the encoded input request
         */
        private fun encodeAuthnRequest(authnRequest: AuthnRequest): String {
            val authnRequestString = authnRequestToString(authnRequest)
            Log.debugWithSupplier { authnRequestString.prettyPrintXml() }
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
                    .get(Common.getSingleSignOnLocation(REDIRECT_BINDING))
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
            val idpResponse = getServiceProvider(IdpResponder::class)
                    .getIdpRedirectResponse(response).decorate()
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom
            ResponseProtocolVerifier(responseDom, ID, acsUrl[HTTP_REDIRECT]).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_REDIRECT]).verify()
        }

        "Redirect AuthnRequest With Relay State Test" {
            Log.debugWithSupplier { "Redirect AuthnRequest With Relay State Test" }
            val authnRequest = createDefaultAuthnRequest()
            val encodedRequest = encodeAuthnRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST, encodedRequest,
                    TestCommon.EXAMPLE_RELAY_STATE)

            // Get response from AuthnRequest
            val response = sendAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

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
            val idpResponse = getServiceProvider(IdpResponder::class)
                    .getIdpRedirectResponse(response).decorate()
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom
            ResponseProtocolVerifier(responseDom, TestCommon.ID, acsUrl[HTTP_REDIRECT]).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_REDIRECT]).verify()
        }

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
                    TestCommon.RELAY_STATE_GREATER_THAN_80_BYTES)

            // Get response from AuthnRequest
            val response = sendAuthnRequest(queryParams)

            val idpResponse = TestCommon.parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            CoreVerifier(responseDom).verifyErrorStatusCode(
                    samlErrorCode = SAMLBindings_3_4_3_a1,
                    expectedStatusCode = TestCommon.REQUESTER)
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
            // using !! here because null is already checked with safe call
            queryParams.set(SAML_REQUEST, queryParams[SAML_REQUEST]
                    ?.substring(0, queryParams[SAML_REQUEST]!!.length / 2))

            // Get response from AuthnRequest
            val response = sendAuthnRequest(queryParams)

            val idpResponse = TestCommon.parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            CoreVerifier(responseDom).verifyErrorStatusCode(
                    SAMLBindings_3_4_3_a1,
                    TestCommon.REQUESTER)
        }.config(enabled = false)

        "Empty Redirect AuthnRequest Test" {
            Log.debugWithSupplier { "Empty Redirect AuthnRequest Test" }
            val authnRequest = AuthnRequestBuilder().buildObject()
            val encodedRequest = encodeAuthnRequest(authnRequest)
            val queryParams = mutableMapOf<String, String>()
            queryParams.put(SAML_REQUEST, encodedRequest)

            val response = sendAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = TestCommon.parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            CoreVerifier(responseDom).verifyErrorStatusCode(SAMLProfiles_4_1_4_1_a,
                    TestCommon.REQUESTER)
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

            val idpResponse = TestCommon.parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            CoreVerifier(responseDom).verifyErrorStatusCode(SAMLProfiles_4_1_4_1_b,
                    TestCommon.REQUESTER)
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

            val idpResponse = TestCommon.parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()
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
            val idpResponse = TestCommon.parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()
            val responseDom = idpResponse.responseDom
            CoreVerifier(responseDom).verifyErrorStatusCode(SAMLCore_3_2_1_e, TestCommon.REQUESTER)
        }.config(enabled = false)
    }
}
