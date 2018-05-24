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
import org.codice.compliance.LENIENT_ERROR_VERIFICATION
import org.codice.compliance.SAMLBindings_3_5_3_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_2_1_e
import org.codice.compliance.SAMLProfiles_4_1_4_1_a
import org.codice.compliance.SAMLProfiles_4_1_4_1_b
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
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
import org.opensaml.saml.saml2.core.impl.NameIDBuilder
import org.opensaml.saml.saml2.core.impl.SubjectBuilder

class PostSSOErrorTest : StringSpec() {
    init {
        RestAssured.useRelaxedHTTPSValidation()
        val isLenient = System.getProperty(LENIENT_ERROR_VERIFICATION) == "true"

        "Bindings 3.5.3: POST AuthnRequest With Relay State Greater Than 80 Bytes Test" {
            try {
                Log.debugWithSupplier {
                    "Bindings 3.5.3: POST AuthnRequest With Relay State Greater Than 80 Bytes Test"
                }
                val authnRequest = createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_POST)
                val encodedRequest =
                        signAndEncodeToString(authnRequest, RELAY_STATE_GREATER_THAN_80_BYTES)
                val response = sendPostAuthnRequest(encodedRequest)

                if (!isLenient || !BindingVerifier.isErrorHttpStatusCode(response.statusCode)) {
                    val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                    CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                        samlErrorCode = SAMLBindings_3_5_3_a,
                        expectedStatusCode = REQUESTER)
                }
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }

        "Profiles 4.1.4.1: Empty POST AuthnRequest Test" {
            try {
                Log.debugWithSupplier { "Profiles 4.1.4.1: Empty POST AuthnRequest Test" }
                val authnRequest = AuthnRequestBuilder().buildObject().apply {
                }

                val encodedRequest = signAndEncodeToString(authnRequest, EXAMPLE_RELAY_STATE)
                val response = sendPostAuthnRequest(encodedRequest)

                if (!isLenient || !BindingVerifier.isErrorHttpStatusCode(response.statusCode)) {
                    val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                    CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                        samlErrorCode = SAMLProfiles_4_1_4_1_a,
                        expectedStatusCode = REQUESTER)
                    ProfilesVerifier(samlResponseDom).verifyErrorResponseAssertion()
                }
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }

        // TODO - DDF responds with a successful response. Re-enable test when DDF handles this
        "Profiles 4.1.4.1: POST AuthnRequest With Subject Containing an Invalid Name ID Test"
            .config(enabled = false) {
                try {
                    Log.debugWithSupplier {
                        "Profiles 4.1.4.1: POST AuthnRequest With Subject Containing an Invalid " +
                            "Name ID Test"
                    }
                    val authnRequest =
                        createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_POST).apply {
                            subject = SubjectBuilder().buildObject().apply {
                                nameID = NameIDBuilder().buildObject().apply {
                                    value = "UNKNOWN NAME ID VALUE"
                                }
                            }
                        }
                    val encodedRequest = signAndEncodeToString(authnRequest, EXAMPLE_RELAY_STATE)
                    val response = sendPostAuthnRequest(encodedRequest)

                    if (!isLenient || !BindingVerifier.isErrorHttpStatusCode(response.statusCode)) {
                        val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                        CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                            samlErrorCode = SAMLProfiles_4_1_4_1_b,
                            expectedStatusCode = REQUESTER)
                        ProfilesVerifier(samlResponseDom)
                            .verifyErrorResponseAssertion(SAMLProfiles_4_1_4_1_b)
                    }
                } catch (e: SAMLComplianceException) {
                    throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
                }
            }

        "Core 3.2.1: POST AuthnRequest With Non-Matching Destination" {
            try {
                Log.debugWithSupplier {
                    "Core 3.2.1: POST AuthnRequest With Non-Matching Destination"
                }
                val authnRequest = createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_POST).apply {
                    destination = INCORRECT_DESTINATION
                }
                val encodedRequest = signAndEncodeToString(authnRequest)
                val response = sendPostAuthnRequest(encodedRequest)

                if (!isLenient || !BindingVerifier.isErrorHttpStatusCode(response.statusCode)) {
                    val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                    CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                        samlErrorCode = SAMLCore_3_2_1_e,
                        expectedStatusCode = REQUESTER)
                }
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }
    }
}
