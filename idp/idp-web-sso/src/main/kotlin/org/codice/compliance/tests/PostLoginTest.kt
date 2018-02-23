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
package org.codice.compliance.tests

import com.jayway.restassured.RestAssured
import com.jayway.restassured.RestAssured.given
import io.kotlintest.matchers.shouldBe
import io.kotlintest.matchers.shouldNotBe
import io.kotlintest.specs.StringSpec
import org.apache.cxf.rs.security.saml.sso.SSOConstants
import org.codice.compliance.*
import org.codice.compliance.bindings.verifyPost
import org.codice.compliance.core.verifyCore
import org.codice.compliance.profiles.verifySsoProfile
import org.codice.compliance.saml.plugin.IdpResponder
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.Decoder
import org.codice.security.sign.Encoder
import java.io.IOException

class PostLoginTest : StringSpec({
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
                .post(getSingleSignonLocation(SamlProtocol.POST_BINDING))

        response.statusCode shouldBe 200
        val idpResponse = getServiceProvider(IdpResponder::class.java).getIdpPostResponse(response)
        assertPostResponse(idpResponse)
    }

    "POST AuthnRequest With Relay State Test" {
        val authnRequest = generateAndRetrieveAuthnRequest()
        val encodedRequest = Encoder.encodePostMessage(authnRequest, RELAY_STATE)
        val response = given()
                .urlEncodingEnabled(false)
                .body(encodedRequest)
                .contentType("application/x-www-form-urlencoded")
                .log()
                .ifValidationFails()
                .`when`()
                .post(getSingleSignonLocation(SamlProtocol.POST_BINDING))

        response.statusCode shouldBe 200
        val idpResponse = getServiceProvider(IdpResponder::class.java).getIdpPostResponse(response)
        assertPostResponse(idpResponse)
    }
})

/**
 * Parses a POST idp response
 * @param - String response ordered in any order.
 * For example, "SAMLResponse=**SAMLResponse**&RelayState=**RelayState**
 * @return - A map from String key (SAMLResponse, RelayState) to String value
 */
fun parseFinalPostResponse(idpResponse: String): Map<String, String> {
    val parsedResponse = mutableMapOf<String, String>()

    val splitResponse = idpResponse.split("&")
    splitResponse.forEach {
        when {
            it.startsWith(SSOConstants.SAML_RESPONSE) -> parsedResponse.put(SSOConstants.SAML_RESPONSE, it.replace("SAMLResponse=", ""))
            it.startsWith(SSOConstants.RELAY_STATE) -> parsedResponse.put(SSOConstants.RELAY_STATE, it.replace("RelayState=", ""))
        }
    }
    return parsedResponse
}

fun assertPostResponse(response: String) {
    val parsedResponse = parseFinalPostResponse(response)
    val samlResponse = parsedResponse["SAMLResponse"]
    val decodedMessage: String
    try {
        decodedMessage = Decoder.decodePostMessage(samlResponse)
    } catch (e: IOException) {
        throw SAMLComplianceException.create("SAMLBindings.3.5.4")
    }

    decodedMessage shouldNotBe null
    val responseDomElement = buildDom(decodedMessage)
    verifyCore(responseDomElement)
    verifySsoProfile(responseDomElement)
    verifyPost(responseDomElement, parsedResponse)
}
