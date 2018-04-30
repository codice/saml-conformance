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
import org.codice.compliance.SAMLBindings_3_5_3_a
import org.codice.compliance.SAMLCore_3_2_1_e
import org.codice.compliance.SAMLProfiles_4_1_4_1_a
import org.codice.compliance.SAMLProfiles_4_1_4_1_b
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.INCORRECT_ACS_URL
import org.codice.compliance.utils.TestCommon.Companion.INCORRECT_DESTINATION
import org.codice.compliance.utils.TestCommon.Companion.RELAY_STATE_GREATER_THAN_80_BYTES
import org.codice.compliance.utils.TestCommon.Companion.REQUESTER
import org.codice.compliance.utils.TestCommon.Companion.createDefaultAuthnRequest
import org.codice.compliance.utils.TestCommon.Companion.sendPostAuthnRequest
import org.codice.compliance.utils.TestCommon.Companion.signAndEncodeToString
import org.codice.compliance.utils.getBindingVerifier
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.core.CoreVerifier
import org.codice.compliance.verification.profile.ProfilesVerifier
import org.codice.security.saml.SamlProtocol
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.SubjectBuilder

class PostSSOErrorTest : StringSpec() {
    init {
        RestAssured.useRelaxedHTTPSValidation()

        // Negative Path Tests
        "POST AuthnRequest With Relay State Greater Than 80 Bytes Test" {
            Log.debugWithSupplier {
                "POST AuthnRequest With Relay State Greater Than 80 Bytes Test"
            }
            val authnRequest = createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_POST)
            val encodedRequest =
                    signAndEncodeToString(authnRequest, RELAY_STATE_GREATER_THAN_80_BYTES)
            val response = sendPostAuthnRequest(encodedRequest)

            val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

            CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                    samlErrorCode = SAMLBindings_3_5_3_a,
                    expectedStatusCode = REQUESTER)
        }.config(enabled = false)

        "Empty POST AuthnRequest Test" {
            Log.debugWithSupplier { "Empty POST AuthnRequest Test" }
            val authnRequest = AuthnRequestBuilder().buildObject().apply {
            }

            val encodedRequest = signAndEncodeToString(authnRequest, EXAMPLE_RELAY_STATE)
            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

            CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                    samlErrorCode = SAMLProfiles_4_1_4_1_a,
                    expectedStatusCode = REQUESTER)
            ProfilesVerifier(samlResponseDom).verifyErrorResponseAssertion()
        }.config(enabled = false)

        "POST AuthnRequest With Empty Subject Test" {
            Log.debugWithSupplier { "POST AuthnRequest With Empty Subject Test" }
            val authnRequest = createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_POST).apply {
                subject = SubjectBuilder().buildObject()
            }

            val encodedRequest = signAndEncodeToString(authnRequest, EXAMPLE_RELAY_STATE)
            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

            CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                    samlErrorCode = SAMLProfiles_4_1_4_1_b,
                    expectedStatusCode = REQUESTER)
            ProfilesVerifier(samlResponseDom).verifyErrorResponseAssertion(SAMLProfiles_4_1_4_1_b)
        }.config(enabled = false)

        "POST AuthnRequest With Incorrect ACS URL And Index Test" {
            Log.debugWithSupplier { "POST AuthnRequest With Incorrect ACS URL And Index Test" }
            val authnRequest = createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_POST).apply {
                assertionConsumerServiceURL = INCORRECT_ACS_URL
                assertionConsumerServiceIndex = -1
            }

            val encodedRequest = signAndEncodeToString(authnRequest, EXAMPLE_RELAY_STATE)
            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

            // DDF returns a valid response to the incorrect url
        }.config(enabled = false)

        "POST AuthnRequest With Non-Matching Destination" {
            Log.debugWithSupplier { "POST AuthnRequest With Non-Matching Destination" }
            val authnRequest = createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_POST).apply {
                destination = INCORRECT_DESTINATION
            }

            val encodedRequest = signAndEncodeToString(authnRequest)
            val response = sendPostAuthnRequest(encodedRequest)

            BindingVerifier.verifyHttpStatusCode(response.statusCode)
            val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

            CoreVerifier.verifyErrorStatusCode(samlResponseDom, samlErrorCode = SAMLCore_3_2_1_e,
                    expectedStatusCode = REQUESTER)
        }.config(enabled = false)
    }
}
