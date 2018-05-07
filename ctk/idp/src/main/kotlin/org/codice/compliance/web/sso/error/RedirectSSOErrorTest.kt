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
import de.jupf.staticlog.Log
import io.kotlintest.specs.StringSpec
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.codice.compliance.SAMLBindings_3_4_3_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_2_1_e
import org.codice.compliance.SAMLProfiles_4_1_4_1_a
import org.codice.compliance.SAMLProfiles_4_1_4_1_b
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.utils.TestCommon.Companion.INCORRECT_ACS_URL
import org.codice.compliance.utils.TestCommon.Companion.INCORRECT_DESTINATION
import org.codice.compliance.utils.TestCommon.Companion.RELAY_STATE_GREATER_THAN_80_BYTES
import org.codice.compliance.utils.TestCommon.Companion.REQUESTER
import org.codice.compliance.utils.TestCommon.Companion.createDefaultAuthnRequest
import org.codice.compliance.utils.TestCommon.Companion.encodeAuthnRequest
import org.codice.compliance.utils.TestCommon.Companion.sendRedirectAuthnRequest
import org.codice.compliance.utils.getBindingVerifier
import org.codice.compliance.verification.core.CoreVerifier
import org.codice.compliance.verification.profile.ProfilesVerifier
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.SimpleSign
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.SubjectBuilder

class RedirectSSOErrorTest : StringSpec() {
    init {
        RestAssured.useRelaxedHTTPSValidation()

        // Negative Path Tests
        "Redirect AuthnRequest With Relay State Greater Than 80 Bytes Test" {
            try {
                Log.debugWithSupplier {
                    "Redirect AuthnRequest With Relay State Greater Than 80 Bytes Test"
                }
                val authnRequest =
                        createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_REDIRECT)
                val encodedRequest = encodeAuthnRequest(authnRequest)
                val queryParams = SimpleSign().signUriString(
                        SAML_REQUEST,
                        encodedRequest,
                        RELAY_STATE_GREATER_THAN_80_BYTES)

                // Get response from AuthnRequest
                val response = sendRedirectAuthnRequest(queryParams)

                val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                        samlErrorCode = SAMLBindings_3_4_3_a,
                        expectedStatusCode = REQUESTER)
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }

        "Redirect Incomplete AuthnRequest In URL Query Test" {
            try {
                Log.debugWithSupplier {
                    "Redirect Incomplete AuthnRequest In URL Query Test"
                }
                val authnRequest =
                        createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_REDIRECT)
                val encodedRequest = encodeAuthnRequest(authnRequest)
                val queryParams = SimpleSign().signUriString(
                        SAML_REQUEST,
                        encodedRequest,
                        null)
                val qpSamlReq = queryParams[SAML_REQUEST]
                queryParams.set(SAML_REQUEST, qpSamlReq?.substring(0, qpSamlReq.length / 2))

                // Get response from AuthnRequest
                val response = sendRedirectAuthnRequest(queryParams)

                val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                        samlErrorCode = SAMLBindings_3_4_3_a,
                        expectedStatusCode = REQUESTER)
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }

        "Empty Redirect AuthnRequest Test" {
            try {
                Log.debugWithSupplier { "Empty Redirect AuthnRequest Test" }
                val authnRequest = AuthnRequestBuilder().buildObject()
                val encodedRequest = encodeAuthnRequest(authnRequest)
                val queryParams = mapOf(SAML_REQUEST to encodedRequest)

                val response = sendRedirectAuthnRequest(queryParams)

                val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                        samlErrorCode = SAMLProfiles_4_1_4_1_a,
                        expectedStatusCode = REQUESTER)
                ProfilesVerifier(samlResponseDom).verifyErrorResponseAssertion()
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }

        "Redirect AuthnRequest With Empty Subject Test" {
            try {
                Log.debugWithSupplier { "Redirect AuthnRequest With Empty Subject Test" }
                val authnRequest =
                        createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_REDIRECT).apply {
                            subject = SubjectBuilder().buildObject()
                        }
                val encodedRequest = encodeAuthnRequest(authnRequest)
                val queryParams = SimpleSign().signUriString(
                        SAML_REQUEST,
                        encodedRequest,
                        null)

                // Get response from AuthnRequest
                val response = sendRedirectAuthnRequest(queryParams)

                val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                        samlErrorCode = SAMLProfiles_4_1_4_1_b,
                        expectedStatusCode = REQUESTER)
                ProfilesVerifier(samlResponseDom)
                        .verifyErrorResponseAssertion(SAMLProfiles_4_1_4_1_b)
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }

        "Redirect AuthnRequest With Incorrect ACS URL And Index Test" {
            try {
                Log.debugWithSupplier {
                    "Redirect AuthnRequest With " +
                            "Incorrect ACS URL And Index Test"
                }
                val authnRequest =
                        createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_REDIRECT).apply {
                            assertionConsumerServiceURL = INCORRECT_ACS_URL
                            assertionConsumerServiceIndex = -1
                        }
                val encodedRequest = encodeAuthnRequest(authnRequest)
                val queryParams =
                        SimpleSign().signUriString(SAML_REQUEST, encodedRequest, null)

                // Get response from AuthnRequest
                val response = sendRedirectAuthnRequest(queryParams)

                response.getBindingVerifier().decodeAndVerifyError()

                // DDF returns a valid response to the incorrect url
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }

        "Redirect AuthnRequest With Non-Matching Destination" {
            try {
                Log.debugWithSupplier { "Redirect AuthnRequest With Non-Matching Destination" }
                val authnRequest =
                        createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_REDIRECT).apply {
                            destination = INCORRECT_DESTINATION
                        }
                val encodedRequest = encodeAuthnRequest(authnRequest)
                val queryParams =
                        SimpleSign().signUriString(SAML_REQUEST, encodedRequest, null)

                // Get response from AuthnRequest
                val response = sendRedirectAuthnRequest(queryParams)

                val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                        samlErrorCode = SAMLCore_3_2_1_e,
                        expectedStatusCode = REQUESTER)
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }
    }
}
