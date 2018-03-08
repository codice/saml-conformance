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
import com.jayway.restassured.builder.RequestSpecBuilder
import com.jayway.restassured.response.Response
import io.kotlintest.matchers.shouldBe
import org.apache.commons.lang3.StringUtils
import org.apache.cxf.rs.security.saml.sso.SSOConstants.RELAY_STATE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.codice.compliance.Common
import org.codice.compliance.saml.plugin.IdpResponder
import org.codice.security.saml.SamlProtocol
import org.kohsuke.MetaInfServices


@MetaInfServices
class IdpResponderProvider : IdpResponder {
    companion object {
        val REDIR_REGEX = """var encoded\s*=\s*"(.*)";""".toRegex()
    }

    override fun getIdpRedirectResponse(originalResponse: Response): String? {
        val response = parseResponseAndSendRequest(originalResponse)
        response.statusCode() shouldBe 200

        /*************************
         * <html>
         * <head>
         * ...
         * <script type="text/javascript">
         *  window.onload = function () {
         *      window.setTimeout(function () {
         *          window.setInterval(function () {
         *              var encoded = "SAMLResponse HERE";
         *              window.location.replace(encoded);
         *          }, 2000);
         *      }, 100);
         *  }
         * </script>
         * ...
         ************************/
        val script = response
                .then()
                .extract()
                .htmlPath()
                .getNode("html")
                .getNode("head")
                .getNode("script")
                .value()

        return REDIR_REGEX.find(script)?.groups?.get(1)?.value
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
         * <input type="hidden" name="RelayState" value="relayState"/>
         * ...
         ************************/
        val form = response
                .then()
                .extract()
                .htmlPath()
                .getNode("html")
                .getNode("body")
                .getNode("form")

        val samlResponse = form
                .getNodes("input")[1]
                .getAttribute("value")

        val relayState = form
                .getNodes("input")[2]
                .getAttribute("value")

        return if (StringUtils.isNoneBlank(relayState))
            "$RELAY_STATE=$relayState&$SAML_RESPONSE=$samlResponse"
        else "$SAML_RESPONSE=$samlResponse"
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
        val idpState = response
                .then()
                .extract()
                .htmlPath()
                .getNode("html")
                .getNode("head")
                .getNodes("script")[0]
                .value()
                .toString()
                .trim()
                .replace("window.idpState = ", "")
                .replace(";", "")

        val queryParams = ObjectMapper()
                .readValue(idpState, MutableMap::class.java) as MutableMap<String, String>

        queryParams["AuthMethod"] = "up"
        val requestSpec = RequestSpecBuilder().addParams(queryParams).build()

        return RestAssured
                .given(requestSpec)
                .auth()
                .preemptive()
                .basic("admin", "admin")
                .log()
                .ifValidationFails()
                .`when`()
                .get(Common.getSingleSignOnLocation(SamlProtocol.POST_BINDING) + "/sso")
    }
}
