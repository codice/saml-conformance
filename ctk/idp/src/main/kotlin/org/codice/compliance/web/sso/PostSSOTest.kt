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
import io.kotlintest.specs.StringSpec
import org.apache.wss4j.common.saml.builder.SAML2Constants
import org.codice.compliance.saml.plugin.IdpSSOResponder
import org.codice.compliance.utils.TestCommon.Companion.ENCRYPTED_ID
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.createDefaultAuthnRequest
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.compliance.utils.TestCommon.Companion.getImplementation
import org.codice.compliance.utils.TestCommon.Companion.sendPostAuthnRequest
import org.codice.compliance.utils.TestCommon.Companion.signAndEncodePostRequestToString
import org.codice.compliance.utils.getBindingVerifier
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.core.responses.CoreAuthnRequestProtocolVerifier
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder

class PostSSOTest : StringSpec() {
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
            SingleSignOnProfileVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        "POST AuthnRequest With Relay State Test (relay state verification from BindingVerifier)" {
            val authnRequest = createDefaultAuthnRequest(HTTP_POST)
            val encodedRequest = signAndEncodePostRequestToString(authnRequest, EXAMPLE_RELAY_STATE)
            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForPostRequest(response)
            val samlResponseDom =
                    finalHttpResponse.getBindingVerifier().apply {
                        isRelayStateGiven = true
                    }.decodeAndVerify()

            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        "POST AuthnRequest Without ACS Url (verify the ACS in verifyAssertionConsumerService)" {
            val authnRequest = createDefaultAuthnRequest(HTTP_POST).apply {
                assertionConsumerServiceURL = null
            }
            val encodedRequest = signAndEncodePostRequestToString(authnRequest, EXAMPLE_RELAY_STATE)
            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForPostRequest(response)
            val samlResponseDom = finalHttpResponse.getBindingVerifier().decodeAndVerify()

            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        // TODO When DDF is fixed to return NameID format based on NameIDPolicy,
        // re-enable this test
        ("POST AuthnRequest With Email NameIDPolicy Format Test (NameIDPolicy verification in " +
            "CoreAuthnRequestProtocolVerifier)").config (enabled = false) {
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

            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        // TODO When DDF is fixed to return NameID format based on NameIDPolicy,
        // re-enable this test
        ("POST AuthnRequest With Encrypted NameIDPolicy Format Test (NameID verification in " +
            "CoreAuthnRequestProtocolVerifier#verifyEncryptedElements)").config(enabled = false) {
            val authnRequest = createDefaultAuthnRequest(HTTP_POST).apply {
                nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
                    format = ENCRYPTED_ID
                    spNameQualifier = currentSPIssuer
                }
            }
            val encodedRequest = signAndEncodePostRequestToString(authnRequest, EXAMPLE_RELAY_STATE)
            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForPostRequest(response)
            val samlResponseDom = finalHttpResponse.getBindingVerifier().decodeAndVerify()

            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }
    }
}
