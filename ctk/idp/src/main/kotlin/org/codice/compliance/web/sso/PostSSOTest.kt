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
import org.apache.cxf.rs.security.saml.sso.SSOConstants
import org.apache.wss4j.common.saml.builder.SAML2Constants
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.Common.Companion.runningDDFProfile
import org.codice.compliance.saml.plugin.IdpSSOResponder
import org.codice.compliance.utils.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.SSOCommon.Companion.createDefaultAuthnRequest
import org.codice.compliance.utils.SSOCommon.Companion.sendPostAuthnRequest
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.compliance.utils.TestCommon.Companion.getImplementation
import org.codice.compliance.utils.TestCommon.Companion.signAndEncodePostRequestToString
import org.codice.compliance.utils.ddfAuthnContextList
import org.codice.compliance.utils.TestCommon.Companion.useDSAServiceProvider
import org.codice.compliance.utils.getBindingVerifier
import org.codice.compliance.utils.sign.SimpleSign
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.core.responses.CoreAuthnRequestProtocolVerifier
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder
import org.codice.security.sign.Encoder
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder
import org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_DSA_SHA256
import org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256

class PostSSOTest : StringSpec() {
    override val defaultTestCaseConfig = TestCaseConfig(tags = setOf(SSO))

    init {
        RestAssured.useRelaxedHTTPSValidation()

        "POST AuthnRequest Test" {
            val authnRequest = createDefaultAuthnRequest(HTTP_POST)
            val encodedRequest = signAndEncodePostRequestToString(authnRequest)
            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForPostRequest(response)
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

        "POST AuthnRequest With Relay State Test" {
            val authnRequest = createDefaultAuthnRequest(HTTP_POST)
            val encodedRequest = signAndEncodePostRequestToString(authnRequest, EXAMPLE_RELAY_STATE)
            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForPostRequest(response)
            // Main goal is to do the relay state verification in the BindingVerifier
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

        "POST AuthnRequest Without ACS Url or ACS Index Test" {
            val authnRequest = createDefaultAuthnRequest(HTTP_POST).apply {
                assertionConsumerServiceURL = null
            }
            val encodedRequest = signAndEncodePostRequestToString(authnRequest, EXAMPLE_RELAY_STATE)
            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForPostRequest(response)
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

        "POST AuthnRequest With Email NameIDPolicy Format Test" {
            val authnRequest = createDefaultAuthnRequest(HTTP_POST).apply {
                nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
                    format = SAML2Constants.NAMEID_FORMAT_EMAIL_ADDRESS
                    spNameQualifier = currentSPIssuer
                }
            }
            val encodedRequest = signAndEncodePostRequestToString(authnRequest, EXAMPLE_RELAY_STATE)
            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForPostRequest(response)
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

        "DDF-Specific: POST AuthnRequest Using SHA256 for Signing Test".config(
                enabled = runningDDFProfile()) {
            useDSAServiceProvider()
            val authnRequest = createDefaultAuthnRequest(HTTP_POST)

            SimpleSign(ALGO_ID_SIGNATURE_RSA_SHA256, ALGO_ID_SIGNATURE_DSA_SHA256).signSamlObject(
                    authnRequest)
            val requestString = TestCommon.samlObjectToString(authnRequest)
            requestString.debugPrettyPrintXml(SSOConstants.SAML_REQUEST)

            val response = sendPostAuthnRequest(
                    Encoder.encodePostMessage(SSOConstants.SAML_REQUEST, requestString))
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForPostRequest(response)
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

        "DDF-Specific: POST AuthnRequest With AuthnContext Test".config(
                enabled = runningDDFProfile()) {
            val reqAuthnContextClassRefs = ddfAuthnContextList
                    .map {
                        AuthnContextClassRefBuilder().buildObject().apply {
                            authnContextClassRef = it
                        }
                    }
                    .toList()

            val authnRequest = createDefaultAuthnRequest(HTTP_POST).apply {
                requestedAuthnContext = RequestedAuthnContextBuilder().buildObject().apply {
                    authnContextClassRefs.addAll(reqAuthnContextClassRefs)
                }
            }

            val encodedRequest = signAndEncodePostRequestToString(authnRequest)
            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForPostRequest(response)
            val samlResponseDom = finalHttpResponse.getBindingVerifier().decodeAndVerify()

            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
                verifyAuthnContextClassRef()
            }
            SingleSignOnProfileVerifier(samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }
    }
}
