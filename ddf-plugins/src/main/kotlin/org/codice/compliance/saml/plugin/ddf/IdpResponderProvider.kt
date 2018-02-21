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
package org.codice.compliance.saml.plugin.ddf

import com.fasterxml.jackson.databind.ObjectMapper
import com.jayway.restassured.RestAssured
import com.jayway.restassured.internal.path.xml.NodeBase
import com.jayway.restassured.internal.path.xml.NodeImpl
import com.jayway.restassured.response.Response
import io.kotlintest.matchers.shouldBe
import org.codice.compliance.saml.plugin.IdpResponder
import org.kohsuke.MetaInfServices
import java.nio.charset.StandardCharsets

@MetaInfServices
class IdpResponderProvider : IdpResponder {

    override fun getIdpRedirectResponse(originalResponse: Response): String? {
        val response = parseResponseAndSendRequest(originalResponse)
        response.statusCode() shouldBe 200

        /*************************
         * <html>
         * <head>
         * ...
         * <script type="text/javascript">
         * **SAMLResponseValueHere**
         * </script>
         * ...
         ************************/
        val nodeBase = response
                .then()
                .extract()
                .htmlPath()
                .getNode("html")
                .getNode("head") as NodeBase
        val script = nodeBase.getNode("script").value()

        val encodedStart = script.indexOf("encoded = \"")
        val encodedEnd = script.indexOf("\";", encodedStart)
        val encoded = script.substring(encodedStart, encodedEnd).replace("encoded = \"", "")
        return encoded
                .split("&")[0]
                .split("?")[1]
                .replace("SAMLResponse=", "")
    }

    override fun getIdpPostResponse(originalResponse: Response): String? {
        val response = parseResponseAndSendRequest(originalResponse)
        response.statusCode() shouldBe 200
        /*************************
         * <html>
         * ...
         * <body>
         * <form id="postform" method="post" action="https://localhost:8993/services/saml/sso">
         * <input class="idp-form-submit" type="submit" style="display:none;"/>
         * <input type="hidden" name="SAMLResponse" value="**SAMLResponseValueHere**"/>
         * ...
         ************************/
        return response
                .then()
                .extract()
                .htmlPath()
                .getNode("html")
                .getNode("body")
                .getNode("form")
                .getNodes("input")[1]
                .getAttribute("value")
    }

    /**
     * Sends request to DDF's /login/sso endpoint with the query parameters
     */
    private fun parseResponseAndSendRequest(response: Response): Response {
        /*************************
         * <html>
         * <head>
         * ...
         * <script type="application/javascript">
         * window.idpState = {**JSONMapWithInformationHere**};
         * </script>
         * ...
         *************************/
        val nodeImpl = response
                .then()
                .extract()
                .htmlPath()
                .getNode("html")
                .getNode("head")
                .getNodes("script")[0] as NodeImpl

        val idpState = nodeImpl
                .value
                .toString()
                .trim()
                .replace("window.idpState = ", "")
                .replace(";", "")

        val queryParams = ObjectMapper()
                .readValue(idpState, MutableMap::class.java) as MutableMap<String, String>

        return RestAssured.given()
                .auth()
                .preemptive()
                .basic("admin", "admin")
                .param("SAMLRequest", queryParams["SAMLRequest"], StandardCharsets.UTF_8.name())
                .param("SigAlg", queryParams["SigAlg"])
                .param("Signature", queryParams["Signature"])
                .param("AuthMethod", "up")
                .param("OriginalBinding", queryParams["OriginalBinding"])
                .log()
                .ifValidationFails()
                .`when`()
                .get("https://localhost:8993/services/idp/login/sso")
    }
}
