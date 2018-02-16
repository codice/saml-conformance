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
import com.jayway.restassured.internal.path.xml.NodeBase
import io.kotlintest.matchers.shouldBe
import java.nio.charset.StandardCharsets

/**
 * Plugable portion of the test.
 *
 * @param queryParams - Query parameters containing
 * 1- SAMLRequest (the original authn request - String)
 * 2- SigAlg (the signature algorithm used - String)
 * 3- Signature (the signature - String)
 * 4- RelayState (the relay state - if there is one - String)
 * 5- SAMLResponse (the body of the response the IdP sends for the initial authn request)
 * @return A string response
 */
fun getIdpResponse(queryParams: Map<String, String>): String {
    val response = RestAssured.given()
            .urlEncodingEnabled(false)
            .auth()
            .preemptive()
            .basic("admin", "admin")
            .param("SAMLRequest", queryParams["SAMLRequest"], StandardCharsets.UTF_8.name())
            .param("SigAlg", queryParams["SigAlg"])
            .param("Signature", queryParams["Signature"])
            .param("AuthMethod", "up")
            .param("OriginalBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
            .log()
            .ifValidationFails()
            .`when`()
            .get("https://localhost:8993/services/idp/login/sso")

    response.statusCode() shouldBe 200

    val script = (response.then().extract().htmlPath().getNode("html").getNode("head") as NodeBase).getNode("script").value()

    val encodedStart = script.indexOf("encoded = \"")
    val encodedEnd = script.indexOf("\";", encodedStart)
    val encoded = script.substring(encodedStart, encodedEnd).replace("encoded = \"", "")
    return encoded.split("&")[0].split("?")[1].replace("SAMLResponse=", "")
}