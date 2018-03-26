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
import de.jupf.staticlog.Log
import io.kotlintest.matchers.shouldBe
import io.kotlintest.specs.StringSpec
import org.apache.wss4j.common.saml.builder.SAML2Constants
import org.codice.compliance.Common
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.prettyPrintXml
import org.codice.compliance.saml.plugin.IdpResponder
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.compliance.utils.TestCommon.Companion.authnRequestToString
import org.codice.compliance.utils.TestCommon.Companion.getServiceProvider
import org.codice.compliance.utils.decorators.bindingVerifier
import org.codice.compliance.utils.decorators.decorate
import org.codice.compliance.verification.core.ResponseProtocolVerifier
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.saml.SamlProtocol.POST_BINDING
import org.codice.security.sign.Encoder
import org.codice.security.sign.SimpleSign
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder

class PostLoginTest : StringSpec() {
    companion object {
        const val HTTP_OK = 200

        /** Sets up positive path tests.
         * @return A string representation of a valid encoded POST AuthnRequest.
         */
        private fun createValidAuthnRequest(): String {
            val authnRequest = AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply {
                    value = TestCommon.SP_ISSUER
                }
                assertionConsumerServiceURL = acsUrl[HTTP_POST]
                id = TestCommon.ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = Common.getSingleSignOnLocation(POST_BINDING)
                protocolBinding = POST_BINDING
                nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
                    allowCreate = true
                    format = SAML2Constants.NAMEID_FORMAT_PERSISTENT
                    spNameQualifier = TestCommon.SP_ISSUER
                }
            }.apply { SimpleSign().signSamlObject(this) }

            val authnRequestString = authnRequestToString(authnRequest)
            Log.debugWithSupplier { authnRequestString.prettyPrintXml() }
            return authnRequestString
        }
    }

    init {
        RestAssured.useRelaxedHTTPSValidation()

        "POST AuthnRequest Test" {
            Log.debugWithSupplier { "Starting POST AuthnRequest Test" }
            val encodedRequest = Encoder.encodePostMessage(createValidAuthnRequest())
            val response = given()
                    .urlEncodingEnabled(false)
                    .body(encodedRequest)
                    .contentType("application/x-www-form-urlencoded")
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .post(Common.getSingleSignOnLocation(POST_BINDING))

            response.statusCode shouldBe HTTP_OK
            val idpResponse = getServiceProvider(IdpResponder::class)
                    .getIdpPostResponse(response).decorate()
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom
            ResponseProtocolVerifier(responseDom, TestCommon.ID, acsUrl[HTTP_POST]).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
        }

        "POST AuthnRequest With Relay State Test" {
            Log.debugWithSupplier { "Starting POST AuthnRequest With Relay State Test" }
            val encodedRequest = Encoder.encodePostMessage(
                    createValidAuthnRequest(), EXAMPLE_RELAY_STATE)
            val response = given()
                    .urlEncodingEnabled(false)
                    .body(encodedRequest)
                    .contentType("application/x-www-form-urlencoded")
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .post(Common.getSingleSignOnLocation(POST_BINDING))

            response.statusCode shouldBe 200
            val idpResponse = getServiceProvider(IdpResponder::class)
                    .getIdpPostResponse(response).decorate().apply {
                        isRelayStateGiven = true
                    }

            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom
            ResponseProtocolVerifier(responseDom, TestCommon.ID, acsUrl[HTTP_POST]).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
        }

        "POST AuthnRequest Without ACS Url Test" {
            Log.debugWithSupplier { "Starting POST AuthnRequest Without ACS Url Test" }
            val authnRequest = AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply {
                    value = TestCommon.SP_ISSUER
                }
                id = TestCommon.ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = Common.getSingleSignOnLocation(POST_BINDING)
                protocolBinding = POST_BINDING
                nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
                    allowCreate = true
                    format = SAML2Constants.NAMEID_FORMAT_PERSISTENT
                    spNameQualifier = TestCommon.SP_ISSUER
                }
            }.apply { SimpleSign().signSamlObject(this) }

            val authnRequestString = authnRequestToString(authnRequest)
            Log.debugWithSupplier { authnRequestString.prettyPrintXml() }

            val encodedRequest = Encoder.encodePostMessage(authnRequestString, EXAMPLE_RELAY_STATE)
            val response = given()
                    .urlEncodingEnabled(false)
                    .body(encodedRequest)
                    .contentType("application/x-www-form-urlencoded")
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .post(Common.getSingleSignOnLocation(POST_BINDING))

            response.statusCode shouldBe HTTP_OK
            val idpResponse = getServiceProvider(IdpResponder::class)
                    .getIdpPostResponse(response).decorate()
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom
            ResponseProtocolVerifier(responseDom, TestCommon.ID, acsUrl[HTTP_POST]).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
        }
    }
}
