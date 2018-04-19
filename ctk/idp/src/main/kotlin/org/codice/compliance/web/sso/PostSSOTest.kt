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
import org.apache.wss4j.common.saml.builder.SAML2Constants
import org.codice.compliance.Common.Companion.getSingleSignOnLocation
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.saml.plugin.IdpSSOResponder
import org.codice.compliance.utils.TestCommon.Companion.AUTHN_REQUEST
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.ID
import org.codice.compliance.utils.TestCommon.Companion.NAMEID_ENCRYPTED
import org.codice.compliance.utils.TestCommon.Companion.SP_ISSUER
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.compliance.utils.TestCommon.Companion.authnRequestToString
import org.codice.compliance.utils.TestCommon.Companion.getServiceProvider
import org.codice.compliance.utils.decorate
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.core.responses.CoreAuthnRequestProtocolVerifier
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.saml.SamlProtocol.POST_BINDING
import org.codice.security.sign.Encoder
import org.codice.security.sign.SimpleSign
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder

class PostSSOTest : StringSpec() {
    companion object {

        /** Sets up positive path tests.
         * @return A string representation of a valid encoded POST AuthnRequest.
         */
        private fun createValidAuthnRequest(): AuthnRequest {
            return AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply {
                    value = SP_ISSUER
                }
                assertionConsumerServiceURL = acsUrl[HTTP_POST]
                id = ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = getSingleSignOnLocation(POST_BINDING)
                protocolBinding = POST_BINDING
            }
        }

        private fun signAndConvertToString(authnRequest: AuthnRequest): String {
            SimpleSign().signSamlObject(authnRequest)
            val authnRequestString = authnRequestToString(authnRequest)
            authnRequestString.debugPrettyPrintXml(AUTHN_REQUEST)
            return authnRequestString
        }

        private fun sendAuthnRequest(encodedRequest: String): Response {
            return given()
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

        "POST AuthnRequest Test" {
            Log.debugWithSupplier { "POST AuthnRequest Test" }
            val authnRequest = createValidAuthnRequest()
            val encodedRequest = Encoder.encodePostMessage(signAndConvertToString(authnRequest))
            val response = sendAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = getServiceProvider(IdpSSOResponder::class)
                    .getPostResponse(response).decorate()
            // TODO When DDF is fixed to return a POST SSO response, uncomment this line
            // SingleSignOnProfileVerifier.verifyBinding(idpResponse)
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom

            CoreAuthnRequestProtocolVerifier(responseDom, ID, acsUrl[HTTP_POST],
                    authnRequest.nameIDPolicy).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
        }

        "POST AuthnRequest With Relay State Test" {
            Log.debugWithSupplier { "POST AuthnRequest With Relay State Test" }
            val authnRequest = createValidAuthnRequest()
            val encodedRequest = Encoder.encodePostMessage(
                    signAndConvertToString(authnRequest), EXAMPLE_RELAY_STATE)
            val response = sendAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = getServiceProvider(IdpSSOResponder::class)
                    .getPostResponse(response).decorate().apply {
                        isRelayStateGiven = true
                    }
            // TODO When DDF is fixed to return a POST SSO response, uncomment this line
            // SingleSignOnProfileVerifier.verifyBinding(idpResponse)
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom

            CoreAuthnRequestProtocolVerifier(responseDom, ID, acsUrl[HTTP_POST],
                    authnRequest.nameIDPolicy).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
        }

        "POST AuthnRequest Without ACS Url Test" {
            Log.debugWithSupplier { "POST AuthnRequest Without ACS Url Test" }
            val authnRequest = createValidAuthnRequest().apply {
                assertionConsumerServiceURL = null
            }

            val authnRequestString = signAndConvertToString(authnRequest)

            val encodedRequest = Encoder.encodePostMessage(
                    authnRequestString,
                    EXAMPLE_RELAY_STATE)

            val response = sendAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = getServiceProvider(IdpSSOResponder::class)
                    .getPostResponse(response).decorate()
            // TODO When DDF is fixed to return a POST SSO response, uncomment this line
            // SingleSignOnProfileVerifier.verifyBinding(idpResponse)
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom

            CoreAuthnRequestProtocolVerifier(responseDom, ID, acsUrl[HTTP_POST],
                    authnRequest.nameIDPolicy).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
        }

        "POST AuthnRequest With Email NameIDPolicy Format Test" {
            Log.debugWithSupplier { "POST AuthnRequest With Email NameID Format Test" }
            val authnRequest = createValidAuthnRequest().apply {
                nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
                    format = SAML2Constants.NAMEID_FORMAT_EMAIL_ADDRESS
                    spNameQualifier = SP_ISSUER
                }
            }

            val authnRequestString = signAndConvertToString(authnRequest)

            val encodedRequest = Encoder.encodePostMessage(
                    authnRequestString,
                    EXAMPLE_RELAY_STATE)

            val response = sendAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = getServiceProvider(IdpSSOResponder::class)
                    .getPostResponse(response).decorate()
            // TODO When DDF is fixed to return a POST SSO response, uncomment this line
            // SingleSignOnProfileVerifier.verifyBinding(idpResponse)
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom
            // Main goal of this test is to do the NameIDPolicy verification in
            // CoreAuthnRequestProtocolVerifier
            CoreAuthnRequestProtocolVerifier(responseDom, ID, acsUrl[HTTP_POST],
                    authnRequest.nameIDPolicy).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
            // TODO When DDF is fixed to return NameID format based on NameIDPolicy,
            // re-enable this test
        }.config(enabled = false)

        "POST AuthnRequest With Encrypted NameIDPolicy Format Test" {
            Log.debugWithSupplier { "POST AuthnRequest With Encrypted NameID Format Test" }
            val authnRequest = createValidAuthnRequest().apply {
                nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
                    format = NAMEID_ENCRYPTED
                    spNameQualifier = SP_ISSUER
                }
            }

            val authnRequestString = signAndConvertToString(authnRequest)

            val encodedRequest = Encoder.encodePostMessage(
                    authnRequestString,
                    EXAMPLE_RELAY_STATE)

            val response = sendAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = getServiceProvider(IdpSSOResponder::class)
                    .getPostResponse(response).decorate()
            // TODO When DDF is fixed to return a POST SSO response, uncomment this line
            // SingleSignOnProfileVerifier.verifyBinding(idpResponse)
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom
            // Main goal of this test is to do the NameID verification
            // in CoreAuthnRequestProtocolVerifier#verifyEncryptedElements
            CoreAuthnRequestProtocolVerifier(responseDom, ID, acsUrl[HTTP_POST],
                    authnRequest.nameIDPolicy).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
            // TODO When DDF is fixed to return NameID format based on NameIDPolicy,
            // re-enable this test
        }.config(enabled = false)
    }
}
