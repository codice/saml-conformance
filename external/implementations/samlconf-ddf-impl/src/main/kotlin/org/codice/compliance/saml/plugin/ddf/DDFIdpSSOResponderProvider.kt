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
import org.codice.compliance.saml.plugin.IdpSSOResponder
import org.codice.security.saml.SamlProtocol
import org.kohsuke.MetaInfServices

@MetaInfServices
class DDFIdpSSOResponderProvider : IdpSSOResponder {
    override fun getResponseForRedirectRequest(originalResponse: Response): Response {
        return parseResponseAndSendRequest(originalResponse)
    }

    override fun getResponseForPostRequest(originalResponse: Response): Response {
        return parseResponseAndSendRequest(originalResponse)
    }

    /** Sends request to DDF's /login/sso endpoint with the query parameters */
    private fun parseResponseAndSendRequest(response: Response): Response {
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

        // TypeToken<Map<String, String>> gets the type of Map<String, String> since it doesn't
        // have a class representation
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
