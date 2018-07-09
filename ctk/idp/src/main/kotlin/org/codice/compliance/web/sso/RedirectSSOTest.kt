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

import io.kotlintest.TestCaseConfig
import io.kotlintest.provided.SSO
import io.kotlintest.specs.StringSpec
import io.restassured.RestAssured
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.apache.wss4j.common.saml.builder.SAML2Constants
import org.codice.compliance.Common.Companion.runningAgainstDDF
import org.codice.compliance.saml.plugin.IdpSSOResponder
import org.codice.compliance.utils.ENCRYPTED_ID
import org.codice.compliance.utils.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.SSOCommon.Companion.createDefaultAuthnRequest
import org.codice.compliance.utils.SSOCommon.Companion.sendRedirectAuthnRequest
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.compliance.utils.TestCommon.Companion.encodeRedirectRequest
import org.codice.compliance.utils.TestCommon.Companion.getImplementation
import org.codice.compliance.utils.TestCommon.Companion.useDSAServiceProvider
import org.codice.compliance.utils.getBindingVerifier
import org.codice.compliance.utils.sign.SimpleSign
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.core.responses.CoreAuthnRequestProtocolVerifier
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder

class RedirectSSOTest : StringSpec() {
    override val defaultTestCaseConfig = TestCaseConfig(tags = setOf(SSO))

    init {
        RestAssured.useRelaxedHTTPSValidation()

        "Redirect AuthnRequest Test" {
            val authnRequest = createDefaultAuthnRequest(HTTP_REDIRECT)
            val encodedRequest = encodeRedirectRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)
            val response = sendRedirectAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForRedirectRequest(
                            response)
            val samlResponseDom = finalHttpResponse.getBindingVerifier().decodeAndVerify()

            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        "Redirect AuthnRequest With Relay State Test" {
            val authnRequest = createDefaultAuthnRequest(HTTP_REDIRECT)
            val encodedRequest = encodeRedirectRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    EXAMPLE_RELAY_STATE)

            val response = sendRedirectAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForRedirectRequest(
                            response)
            val samlResponseDom =
                    finalHttpResponse.getBindingVerifier().apply {
                        isRelayStateGiven = true
                    }.decodeAndVerify()

            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        "Redirect AuthnRequest Without ACS Url or ACS Index Test" {
            val authnRequest = createDefaultAuthnRequest(HTTP_REDIRECT).apply {
                assertionConsumerServiceURL = null
            }
            val encodedRequest = encodeRedirectRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)

            val response = sendRedirectAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForRedirectRequest(
                            response)
            val samlResponseDom = finalHttpResponse.getBindingVerifier().decodeAndVerify()

            // Main goal of this test is to verify the ACS in verifyAssertionConsumerService
            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        "Bindings 3.4.4.1: Redirect AuthnRequest Using DSA1 Signature Algorithm" {
            useDSAServiceProvider()
            val authnRequest = createDefaultAuthnRequest(HTTP_REDIRECT)
            val encodedRequest = encodeRedirectRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)

            val response = sendRedirectAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForRedirectRequest(
                            response)
            val samlResponseDom = finalHttpResponse.getBindingVerifier().decodeAndVerify()

            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        // TODO When DDF is fixed to return NameID format based on NameIDPolicy,
        // re-enable this test
        "Redirect AuthnRequest With Email NameID Format Test".config(
                enabled = !runningAgainstDDF()) {
            val authnRequest = createDefaultAuthnRequest(HTTP_REDIRECT).apply {
                nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
                    format = SAML2Constants.NAMEID_FORMAT_EMAIL_ADDRESS
                    spNameQualifier = currentSPIssuer
                }
            }
            val encodedRequest = encodeRedirectRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)

            val response = sendRedirectAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForRedirectRequest(
                            response)
            val samlResponseDom = finalHttpResponse.getBindingVerifier().decodeAndVerify()

            // Main goal of this test is to do the NameIDPolicy verification in
            // CoreAuthnRequestProtocolVerifier
            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        // TODO When DDF is fixed to return NameID format based on NameIDPolicy,
        // re-enable this test
        "Redirect AuthnRequest With Encrypted NameID Format Test".config(
                enabled = !runningAgainstDDF()) {
            val authnRequest = createDefaultAuthnRequest(HTTP_REDIRECT).apply {
                nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
                    format = ENCRYPTED_ID
                    spNameQualifier = currentSPIssuer
                }
            }
            val encodedRequest = encodeRedirectRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)

            val response = sendRedirectAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForRedirectRequest(
                            response)
            val samlResponseDom = finalHttpResponse.getBindingVerifier().decodeAndVerify()

            // Main goal of this test is to do the NameIDPolicy verification in
            // CoreAuthnRequestProtocolVerifier#verifyEncryptedElements
            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }
    }
}
