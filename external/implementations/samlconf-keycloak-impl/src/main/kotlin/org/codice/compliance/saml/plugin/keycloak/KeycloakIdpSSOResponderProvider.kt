/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.saml.plugin.keycloak

import io.restassured.RestAssured
import io.restassured.response.Response
import org.codice.compliance.saml.plugin.IdpSSOResponder
import org.kohsuke.MetaInfServices

@MetaInfServices
class KeycloakIdpSSOResponderProvider : IdpSSOResponder {

    override fun getResponseForRedirectRequest(originalResponse: Response): Response {
        return postUserForm(originalResponse)
    }

    override fun getResponseForPostRequest(originalResponse: Response): Response {
        val loginPageResponse = RestAssured.given()
                .urlEncodingEnabled(false)
                .cookies(originalResponse.cookies)
                .log()
                .ifValidationFails()
                .`when`()
                .get(originalResponse.getHeader("Location"))

        return postUserForm(loginPageResponse, originalResponse.cookies)
    }

    private fun postUserForm(responseWithForm: Response,
                             cookies: Map<String, String> = responseWithForm.cookies): Response {
        val uriString = responseWithForm
                .then()
                .extract()
                .htmlPath()
                .getNode("html.body.**.find { it.name() == 'form' }")
                .getAttribute("action")

        return RestAssured.given()
                .urlEncodingEnabled(false)
                .cookies(cookies)
                .body("username=admin&password=admin")
                .contentType("application/x-www-form-urlencoded")
                .log()
                .ifValidationFails()
                .`when`()
                .post(uriString)
    }
}
