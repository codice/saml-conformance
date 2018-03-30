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

import com.google.common.reflect.TypeToken
import com.google.gson.Gson
import com.jayway.restassured.RestAssured
import com.jayway.restassured.builder.RequestSpecBuilder
import com.jayway.restassured.response.Response
import org.codice.compliance.Common
import org.codice.compliance.saml.plugin.IdpPostResponse
import org.codice.compliance.saml.plugin.IdpRedirectResponse
import org.codice.compliance.saml.plugin.IdpResponder
import org.codice.security.saml.SamlProtocol
import org.kohsuke.MetaInfServices

@MetaInfServices
class DDFIdpResponderProvider : IdpResponder {
    companion object {
        val REDIR_REGEX = """var encoded\s*=\s*"(.*)";""".toRegex()
    }

    override fun getIdpRedirectResponse(originalResponse: Response): IdpRedirectResponse {

        /*
        * TODO "TODO "Manually change DDF IdP to respond with 302/303 status code for Redirect"
        * When ticket is finished, put in this line:
        *
        return IdpRedirectResponse(parseResponseAndSendRequest(originalResponse))
        *
        * and delete everything below in this method
        */

        val response = parseResponseAndSendRequest(originalResponse)

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

        return IdpRedirectResponse.Builder().apply {
            httpStatusCode(response.statusCode)
            url(REDIR_REGEX.find(script)?.groups?.get(1)?.value)
        }.build()
    }

    override fun getIdpPostResponse(originalResponse: Response): IdpPostResponse {
        return IdpPostResponse(parseResponseAndSendRequest(originalResponse))
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

        val queryParams: MutableMap<String, String> =
                Gson().fromJson(idpState, object : TypeToken<Map<String, String>>() {}.type)

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
