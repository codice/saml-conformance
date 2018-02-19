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

import com.google.common.io.Resources.getResource
import com.jayway.restassured.RestAssured
import com.jayway.restassured.RestAssured.given
import io.kotlintest.matchers.shouldNotBe
import io.kotlintest.specs.StringSpec
import org.codice.compliance.assertions.*
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.Decoder
import org.codice.security.sign.Encoder
import org.codice.security.sign.SimpleSign
import java.nio.charset.StandardCharsets
import java.time.Instant

class RedirectLoginTest : StringSpec({
    val simpleSign = SimpleSign()
    val instant = Instant.now().toString()
    RestAssured.useRelaxedHTTPSValidation()

    "Redirect AuthnRequest Test" {
        val baseRequest = getResource("redirect-authn-request.xml").readText()
        val encodedRequest = Encoder.encodeRedirectMessage(String.format(baseRequest, ACS, DESTINATION, ID, instant, SP_ISSUER))
        val queryParams = simpleSign.signUriString("SAMLRequest", encodedRequest, null)
        val response = given()
                .urlEncodingEnabled(false)
                .param("SAMLRequest", queryParams["SAMLRequest"], StandardCharsets.UTF_8.name())
                .param("SigAlg", queryParams["SigAlg"])
                .param("Signature", queryParams["Signature"])
                .log()
                .ifValidationFails()
                .`when`()
                .get("https://localhost:8993/services/idp/login")

        val idpResponse = getIdpRedirectResponse(response)
        assertRedirectResponse(idpResponse)
    }
})


fun assertRedirectResponse(samlResponse: String) {
    val decodedMessage = Decoder.decodeRedirectMessage(samlResponse)
    decodedMessage shouldNotBe null

    val responseElement = buildDom(decodedMessage)
    assertAllLoginResponse(responseElement, SamlProtocol.REDIRECT_BINDING)
}
