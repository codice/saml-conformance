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

package org.codice.compliance

import io.kotlintest.matchers.shouldNotBe
import org.apache.cxf.rs.security.saml.sso.SSOConstants
import org.codice.compliance.bindings.verifyPost
import org.codice.compliance.bindings.verifyRedirect
import org.codice.compliance.core.verifyCore
import org.codice.compliance.profiles.verifySsoProfile
import org.codice.security.sign.Decoder
import java.io.IOException

fun assertResponse(response: String) {
    if (response.contains("?")) assertRedirectResponse(response)
    else assertPostResponse(response)
}

fun assertRedirectResponse(response: String) {
    val parsedResponse = parseFinalRedirectResponse(response)
    val samlResponse = parsedResponse[SSOConstants.SAML_RESPONSE]
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

fun assertPostResponse(response: String) {
    val parsedResponse = parseFinalPostResponse(response)
    val samlResponse = parsedResponse["SAMLResponse"]
    val decodedMessage: String
    try {
        decodedMessage = Decoder.decodePostMessage(samlResponse)
    } catch (e: IOException) {
        throw SAMLComplianceException.create("SAMLBindings.3.5.4")
    }

    decodedMessage shouldNotBe null
    val responseDomElement = buildDom(decodedMessage)
    verifyCore(responseDomElement)
    verifySsoProfile(responseDomElement)
    verifyPost(responseDomElement, parsedResponse)
}

/**
 * Parses a POST idp response
 * @param - String response ordered in any order.
 * For example, "SAMLResponse=**SAMLResponse**&RelayState=**RelayState**
 * @return - A map from String key (SAMLResponse, RelayState) to String value
 */
fun parseFinalPostResponse(idpResponse: String): Map<String, String> {
    val parsedResponse = mutableMapOf<String, String>()

    val splitResponse = idpResponse.split("&")
    splitResponse.forEach {
        when {
            it.startsWith(SSOConstants.SAML_RESPONSE) -> parsedResponse.put(SSOConstants.SAML_RESPONSE, it.replace("SAMLResponse=", ""))
            it.startsWith(SSOConstants.RELAY_STATE) -> parsedResponse.put(SSOConstants.RELAY_STATE, it.replace("RelayState=", ""))
        }
    }
    return parsedResponse
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
            it.startsWith(SSOConstants.SAML_RESPONSE) -> parsedResponse.put(SSOConstants.SAML_RESPONSE, it.replace("SAMLResponse=", ""))
            it.startsWith(SSOConstants.SIG_ALG) -> parsedResponse.put(SSOConstants.SIG_ALG, it.replace("SigAlg=", ""))
            it.startsWith(SSOConstants.SIGNATURE) -> parsedResponse.put(SSOConstants.SIGNATURE, it.replace("Signature=", ""))
            it.startsWith(SSOConstants.RELAY_STATE) -> parsedResponse.put(SSOConstants.RELAY_STATE, it.replace("RelayState=", ""))
        }
    }
    return parsedResponse
}