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
import io.kotlintest.specs.StringSpec
import org.codice.compliance.Common
import org.codice.compliance.saml.plugin.IdpResponder
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.generateAndRetrieveAuthnRequest
import org.codice.compliance.utils.TestCommon.Companion.getServiceProvider
import org.codice.compliance.utils.decorators.IdpResponseDecoratorFactory
import org.codice.compliance.verification.binding.BindingVerifierFactory
import org.codice.compliance.verification.core.CoreVerifier
import org.codice.compliance.verification.core.ResponseProtocolVerifier
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.Encoder

class PostLoginTest : StringSpec() {
    init {
        RestAssured.useRelaxedHTTPSValidation()

        "POST AuthnRequest Test" {
            val authnRequest = generateAndRetrieveAuthnRequest()
            val encodedRequest = Encoder.encodePostMessage(authnRequest)
            val response = given()
                    .urlEncodingEnabled(false)
                    .body(encodedRequest)
                    .contentType("application/x-www-form-urlencoded")
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .post(Common.getSingleSignOnLocation(SamlProtocol.POST_BINDING))

            val idpResponse = getServiceProvider(IdpResponder::class.java).getIdpPostResponse(response)

            val idpResponseDecorator = IdpResponseDecoratorFactory.getDecorator(idpResponse)

            val bindingVerifier = BindingVerifierFactory.getBindingVerifier(idpResponseDecorator)
            bindingVerifier.verify()
        }

        "POST AuthnRequest With Relay State Test" {
            val authnRequest = generateAndRetrieveAuthnRequest()
            val encodedRequest = Encoder.encodePostMessage(authnRequest, EXAMPLE_RELAY_STATE)
            val response = given()
                    .urlEncodingEnabled(false)
                    .body(encodedRequest)
                    .contentType("application/x-www-form-urlencoded")
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .post(Common.getSingleSignOnLocation(SamlProtocol.POST_BINDING))


            val idpResponse = getServiceProvider(IdpResponder::class.java).getIdpPostResponse(response)

            val idpResponseDecorator = IdpResponseDecoratorFactory.getDecorator(idpResponse).apply {
                isRelayStateGiven = true
            }

            val bindingVerifier = BindingVerifierFactory.getBindingVerifier(idpResponseDecorator)
            bindingVerifier.verify()

            val responseDom = idpResponseDecorator.responseDom!!

            val coreVerifier = CoreVerifier(responseDom)
            coreVerifier.verify()

            val responseProtocolVerifier = ResponseProtocolVerifier(responseDom, TestCommon.ID)
            responseProtocolVerifier.verify()

            val singleSignOnProfileVerifier = SingleSignOnProfileVerifier(responseDom)
            singleSignOnProfileVerifier.verify()
        }
    }
}
