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
import de.jupf.staticlog.Log
import io.kotlintest.specs.StringSpec
import org.apache.wss4j.common.saml.builder.SAML2Constants
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.saml.plugin.IdpSSOResponder
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.NAMEID_ENCRYPTED
import org.codice.compliance.utils.TestCommon.Companion.REQUEST_ID
import org.codice.compliance.utils.TestCommon.Companion.SP_ISSUER
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.compliance.utils.TestCommon.Companion.createDefaultAuthnRequest
import org.codice.compliance.utils.TestCommon.Companion.getServiceProvider
import org.codice.compliance.utils.TestCommon.Companion.sendPostAuthnRequest
import org.codice.compliance.utils.TestCommon.Companion.signAndEncodeToString
import org.codice.compliance.utils.decorate
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.core.responses.CoreAuthnRequestProtocolVerifier
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import org.codice.security.saml.SamlProtocol
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder

class PostSSOTest : StringSpec() {
    init {
        RestAssured.useRelaxedHTTPSValidation()

        "POST AuthnRequest Test" {
            Log.debugWithSupplier { "POST AuthnRequest Test" }
            val authnRequest = createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_POST)
            val encodedRequest = signAndEncodeToString(authnRequest)
            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = getServiceProvider(IdpSSOResponder::class)
                    .getPostResponse(response).decorate()
            // TODO When DDF is fixed to return a POST SSO response, uncomment this line
            // SingleSignOnProfileVerifier.verifyBinding(idpResponse)
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom

            CoreAuthnRequestProtocolVerifier(responseDom, REQUEST_ID, acsUrl[HTTP_POST],
                    authnRequest.nameIDPolicy).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
        }

        "POST AuthnRequest With Relay State Test" {
            Log.debugWithSupplier { "POST AuthnRequest With Relay State Test" }
            val authnRequest = createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_POST)
            val encodedRequest = signAndEncodeToString(authnRequest, EXAMPLE_RELAY_STATE)
            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = getServiceProvider(IdpSSOResponder::class)
                    .getPostResponse(response).decorate().apply {
                        isRelayStateGiven = true
                    }
            // TODO When DDF is fixed to return a POST SSO response, uncomment this line
            // SingleSignOnProfileVerifier.verifyBinding(idpResponse)
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom

            CoreAuthnRequestProtocolVerifier(responseDom, REQUEST_ID, acsUrl[HTTP_POST],
                    authnRequest.nameIDPolicy).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
        }

        "POST AuthnRequest Without ACS Url Test" {
            Log.debugWithSupplier { "POST AuthnRequest Without ACS Url Test" }
            val authnRequest = createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_POST).apply {
                assertionConsumerServiceURL = null
            }

            val encodedRequest = signAndEncodeToString(authnRequest, EXAMPLE_RELAY_STATE)

            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = getServiceProvider(IdpSSOResponder::class)
                    .getPostResponse(response).decorate()
            // TODO When DDF is fixed to return a POST SSO response, uncomment this line
            // SingleSignOnProfileVerifier.verifyBinding(idpResponse)
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom

            CoreAuthnRequestProtocolVerifier(responseDom, REQUEST_ID, acsUrl[HTTP_POST],
                    authnRequest.nameIDPolicy).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
        }

        "POST AuthnRequest With Email NameIDPolicy Format Test" {
            Log.debugWithSupplier { "POST AuthnRequest With Email NameID Format Test" }
            val authnRequest = createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_POST).apply {
                nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
                    format = SAML2Constants.NAMEID_FORMAT_EMAIL_ADDRESS
                    spNameQualifier = SP_ISSUER
                }
            }

            val encodedRequest = signAndEncodeToString(authnRequest, EXAMPLE_RELAY_STATE)

            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = getServiceProvider(IdpSSOResponder::class)
                    .getPostResponse(response).decorate()
            // TODO When DDF is fixed to return a POST SSO response, uncomment this line
            // SingleSignOnProfileVerifier.verifyBinding(idpResponse)
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom
            // Main goal of this test is to do the NameIDPolicy verification in
            // CoreAuthnRequestProtocolVerifier
            CoreAuthnRequestProtocolVerifier(responseDom, REQUEST_ID, acsUrl[HTTP_POST],
                    authnRequest.nameIDPolicy).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
            // TODO When DDF is fixed to return NameID format based on NameIDPolicy,
            // re-enable this test
        }.config(enabled = false)

        "POST AuthnRequest With Encrypted NameIDPolicy Format Test" {
            Log.debugWithSupplier { "POST AuthnRequest With Encrypted NameID Format Test" }
            val authnRequest = createDefaultAuthnRequest(SamlProtocol.Binding.HTTP_POST).apply {
                nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
                    format = NAMEID_ENCRYPTED
                    spNameQualifier = SP_ISSUER
                }
            }
            val encodedRequest = signAndEncodeToString(authnRequest, EXAMPLE_RELAY_STATE)

            val response = sendPostAuthnRequest(encodedRequest)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val idpResponse = getServiceProvider(IdpSSOResponder::class)
                    .getPostResponse(response).decorate()
            // TODO When DDF is fixed to return a POST SSO response, uncomment this line
            // SingleSignOnProfileVerifier.verifyBinding(idpResponse)
            idpResponse.bindingVerifier().verify()

            val responseDom = idpResponse.responseDom
            // Main goal of this test is to do the NameID verification
            // in CoreAuthnRequestProtocolVerifier#verifyEncryptedElements
            CoreAuthnRequestProtocolVerifier(responseDom, REQUEST_ID, acsUrl[HTTP_POST],
                    authnRequest.nameIDPolicy).verify()
            SingleSignOnProfileVerifier(responseDom, acsUrl[HTTP_POST]).verify()
            // TODO When DDF is fixed to return NameID format based on NameIDPolicy,
            // re-enable this test
        }.config(enabled = false)
    }
}
