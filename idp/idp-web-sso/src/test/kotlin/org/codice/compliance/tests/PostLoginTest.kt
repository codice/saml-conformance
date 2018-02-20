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
import org.codice.compliance.bindings.verifyPost
import org.codice.compliance.buildDom
import org.codice.compliance.core.verifyCore
import org.codice.compliance.generateAndRetrieveAuthnRequest
import org.codice.compliance.getAssertionConsumerServiceLocation
import org.codice.compliance.profiles.verifySsoProfile
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.Decoder
import org.codice.security.sign.Encoder

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
                .post(getAssertionConsumerServiceLocation(SamlProtocol.POST_BINDING))

        response.statusCode shouldBe 200
        val idpResponse = getIdpPostResponse(response)
        assertPostResponse(idpResponse)
    }
})

fun assertPostResponse(samlResponse: String) {
    val decodedMessage = Decoder.decodePostMessage(samlResponse)
    decodedMessage shouldNotBe null

    val responseElement = buildDom(decodedMessage)
    verifyCore(responseElement)
    verifySsoProfile(responseElement)
    verifyPost(responseElement)
}
