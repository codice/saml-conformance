/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.saml.plugin.ddf

import com.google.common.reflect.TypeToken
import com.google.gson.Gson
import io.restassured.RestAssured
import io.restassured.builder.RequestSpecBuilder
import io.restassured.response.Response
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
