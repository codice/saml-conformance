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
import com.jayway.restassured.response.Response
import de.jupf.staticlog.Log
import io.kotlintest.specs.StringSpec
import org.apache.wss4j.common.saml.builder.SAML2Constants
import org.codice.compliance.Common.Companion.getSingleSignOnLocation
import org.codice.compliance.SAMLBindings_3_5_3_a
import org.codice.compliance.SAMLCore_3_2_1_e
import org.codice.compliance.SAMLProfiles_4_1_4_1_a
import org.codice.compliance.SAMLProfiles_4_1_4_1_b
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.utils.TestCommon.Companion.AUTHN_REQUEST
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
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
import org.codice.security.saml.SamlProtocol.POST_BINDING
import org.codice.security.sign.Encoder
import org.codice.security.sign.SimpleSign
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder
import org.opensaml.saml.saml2.core.impl.SubjectBuilder

class PostSSOErrorTest : StringSpec() {
    companion object {

        /** Sets up positive path tests.
         * @return A string representation of a valid encoded POST AuthnRequest.
         */
        private fun createValidAuthnRequest(): String {
            val authnRequest = AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply {
                    value = SP_ISSUER
                }
                assertionConsumerServiceURL = acsUrl[HTTP_POST]
                id = ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = getSingleSignOnLocation(POST_BINDING)
                protocolBinding = POST_BINDING
                nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
                    allowCreate = true
                    format = SAML2Constants.NAMEID_FORMAT_PERSISTENT
                    spNameQualifier = SP_ISSUER
                }
                SimpleSign().signSamlObject(this)
            }

            val authnRequestString = authnRequestToString(authnRequest)
            authnRequestString.debugPrettyPrintXml(AUTHN_REQUEST)
            return authnRequestString
        }

        private fun sendAuthnRequest(encodedRequest: String): Response {
            return RestAssured.given()
                    .urlEncodingEnabled(false)
                    .body(encodedRequest)
                    .contentType("application/x-www-form-urlencoded")
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .post(getSingleSignOnLocation(POST_BINDING))
        }
    }

    init {
        RestAssured.useRelaxedHTTPSValidation()

        // Negative Path Tests
        "POST AuthnRequest With Relay State Greater Than 80 Bytes Test" {
            Log.debugWithSupplier {
                "POST AuthnRequest With Relay State Greater Than 80 Bytes Test"
            }
            val encodedRequest = Encoder.encodePostMessage(
                    createValidAuthnRequest(), RELAY_STATE_GREATER_THAN_80_BYTES)
            val response = sendAuthnRequest(encodedRequest)

            val idpResponse = parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            CoreVerifier(responseDom).verifyErrorStatusCode(
                    samlErrorCode = SAMLBindings_3_5_3_a,
                    expectedStatusCode = REQUESTER)
        }.config(enabled = false)

        "Empty POST AuthnRequest Test" {
            Log.debugWithSupplier { "Empty POST AuthnRequest Test" }
            val authnRequest = AuthnRequestBuilder().buildObject().apply {
            }

            val authnRequestString = authnRequestToString(authnRequest)
            authnRequestString.debugPrettyPrintXml(AUTHN_REQUEST)

            val encodedRequest = Encoder.encodePostMessage(authnRequestString,
                    EXAMPLE_RELAY_STATE)
            val response = sendAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            CoreVerifier(responseDom).verifyErrorStatusCode(SAMLProfiles_4_1_4_1_a,
                    REQUESTER)
            ProfilesVerifier(responseDom).verifyErrorResponseAssertion()
        }.config(enabled = false)

        "POST AuthnRequest With Empty Subject Test" {
            Log.debugWithSupplier { "POST AuthnRequest With Empty Subject Test" }
            val authnRequest = AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply {
                    value = SP_ISSUER
                }
                id = ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = getSingleSignOnLocation(POST_BINDING)
                protocolBinding = POST_BINDING
                subject = SubjectBuilder().buildObject()
                SimpleSign().signSamlObject(this)
            }

            val authnRequestString = authnRequestToString(authnRequest)
            authnRequestString.debugPrettyPrintXml(AUTHN_REQUEST)

            val encodedRequest = Encoder.encodePostMessage(authnRequestString,
                    EXAMPLE_RELAY_STATE)
            val response = sendAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            CoreVerifier(responseDom).verifyErrorStatusCode(SAMLProfiles_4_1_4_1_b,
                    REQUESTER)
            ProfilesVerifier(responseDom).verifyErrorResponseAssertion(SAMLProfiles_4_1_4_1_b)
        }.config(enabled = false)

        "POST AuthnRequest With Incorrect ACS URL And Index Test" {
            Log.debugWithSupplier { "POST AuthnRequest With Incorrect ACS URL And Index Test" }
            val authnRequest = AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply {
                    value = SP_ISSUER
                }
                id = ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = getSingleSignOnLocation(POST_BINDING)
                protocolBinding = POST_BINDING
                assertionConsumerServiceURL = INCORRECT_ACS_URL
                assertionConsumerServiceIndex = -1
                SimpleSign().signSamlObject(this)
            }

            val authnRequestString = authnRequestToString(authnRequest)
            authnRequestString.debugPrettyPrintXml(AUTHN_REQUEST)

            val encodedRequest = Encoder.encodePostMessage(authnRequestString,
                    EXAMPLE_RELAY_STATE)
            val response = sendAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            // DDF returns a valid response to the incorrect url
        }.config(enabled = false)

        "POST AuthnRequest With Non-Matching Destination" {
            Log.debugWithSupplier { "POST AuthnRequest With Non-Matching Destination" }
            val authnRequest = AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply {
                    value = SP_ISSUER
                }
                assertionConsumerServiceURL = acsUrl[HTTP_POST]
                id = ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = INCORRECT_DESTINATION
                protocolBinding = POST_BINDING
                nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
                    allowCreate = true
                    format = SAML2Constants.NAMEID_FORMAT_PERSISTENT
                    spNameQualifier = SP_ISSUER
                }
                SimpleSign().signSamlObject(this)
            }

            val authnRequestString = authnRequestToString(authnRequest)
            authnRequestString.debugPrettyPrintXml(AUTHN_REQUEST)

            val encodedRequest = Encoder.encodePostMessage(authnRequestString)
            val response = sendAuthnRequest(encodedRequest)

            BindingVerifier.verifyHttpStatusCode(response.statusCode)
            val idpResponse = parseErrorResponse(response)
            idpResponse.bindingVerifier().verifyError()

            val responseDom = idpResponse.responseDom
            CoreVerifier(responseDom).verifyErrorStatusCode(SAMLCore_3_2_1_e, REQUESTER)
        }.config(enabled = false)
    }
}
