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
import org.apache.cxf.rs.security.saml.sso.SSOConstants
import org.codice.compliance.*
import org.codice.compliance.bindings.verifyRedirect
import org.codice.compliance.core.verifyCore
import org.codice.compliance.profiles.verifySsoProfile
import org.codice.compliance.saml.plugin.IdpResponder
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.Decoder
import org.codice.security.sign.Encoder
import org.codice.security.sign.SimpleSign
import java.io.IOException
import java.nio.charset.StandardCharsets
import java.time.Instant

class RedirectLoginTest : StringSpec({
    RestAssured.useRelaxedHTTPSValidation()

    "Redirect AuthnRequest Test" {
        val queryParams = setupAuthnRequest(null)

        // Get response from AuthnRequest
        val response = given()
                .urlEncodingEnabled(false)
                .param("SAMLRequest", queryParams["SAMLRequest"], StandardCharsets.UTF_8.name())
                .param("SigAlg", queryParams[SSOConstants.SIG_ALG])
                .param("Signature", queryParams[SSOConstants.SIGNATURE])
                .log()
                .ifValidationFails()
                .`when`()
                .get(getSingleSignonLocation(SamlProtocol.REDIRECT_BINDING))

        val idpResponse = getServiceProvider(IdpResponder::class.java).getIdpRedirectResponse(response)
        assertRedirectResponse(idpResponse)
    }
})

fun setupAuthnRequest(relayState : String?): Map<String, String> {
    val baseRequest = getResource("redirect-authn-request.xml").readText()
    val encodedRequest = Encoder.encodeRedirectMessage(String.format(baseRequest, ACS, DESTINATION, ID, Instant.now().toString(), SP_ISSUER))
    return SimpleSign().signUriString("SAMLRequest", encodedRequest, relayState)
}

/**
 * Parses a redirect idp response
 * @param - String response ordered in any order.
 * For example, "https://host:port/location?SAMLResponse=**SAMLResponse**&SigAlg=**SigAlg**&Signature=**Signature**
 * @return - A map from String key (Location, SAMLResponse, SigAlg, Signature, RelayState) to String value
 */
fun parseFinalRedirectResponse(idpResponse: String): Map<String, String> {
    val parsedResponse = mutableMapOf<String, String>()
    parsedResponse.put("Location", idpResponse.split("?")[0])

    val splitResponse = idpResponse.split("?")[1].split("&")
    splitResponse.forEach {
        when {
            it.startsWith("SAMLResponse") -> parsedResponse.put("SAMLResponse", it.replace("SAMLResponse=", ""))
            it.startsWith("SigAlg") -> parsedResponse.put("SigAlg", it.replace("SigAlg=", ""))
            it.startsWith("Signature") -> parsedResponse.put("Signature", it.replace("Signature=", ""))
            it.startsWith("RelayState") -> parsedResponse.put("RelayState", it.replace("RelayState=", ""))
        }
    }
    return parsedResponse
}

fun assertRedirectResponse(response: String) {
    val parsedResponse = parseFinalRedirectResponse(response)
    val samlResponse = parsedResponse["SAMLResponse"]
    val decodedMessage: String
    try {
        decodedMessage = Decoder.decodeRedirectMessage(samlResponse)
    } catch (e: IOException) {
        throw SAMLComplianceException.create("SAMLBindings.3.4.4.1")
    }

    decodedMessage shouldNotBe null
    val responseElement = buildDom(decodedMessage)
    verifyCore(responseElement)
    verifySsoProfile(responseElement)
    verifyRedirect(responseElement, parsedResponse)
}
