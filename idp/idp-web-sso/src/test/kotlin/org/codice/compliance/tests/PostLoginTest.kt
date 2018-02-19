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
import org.apache.cxf.helpers.DOMUtils
import org.apache.wss4j.common.saml.builder.SAML2Constants
import org.codice.compliance.assertions.*
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.Decoder
import org.codice.security.sign.Encoder
import org.codice.security.sign.SimpleSign
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.apache.wss4j.common.util.DOM2Writer
import org.apache.wss4j.common.saml.OpenSAMLUtil
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder

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
                .post("https://localhost:8993/services/idp/login")

        response.statusCode shouldBe 200
        val idpResponse = getIdpPostResponse(response)
        assertPostResponse(idpResponse)
    }
})

fun assertPostResponse(samlResponse: String) {
    val decodedMessage = Decoder.decodePostMessage(samlResponse)
    decodedMessage shouldNotBe null

    val responseElement = buildDom(decodedMessage)
    assertAllLoginResponse(responseElement, SamlProtocol.POST_BINDING)
}
