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
import org.apache.cxf.rs.security.saml.sso.SSOConstants.*
import org.codice.compliance.bindings.verifyPost
import org.codice.compliance.bindings.verifyRedirect
import org.codice.compliance.core.verifyCore
import org.codice.compliance.core.verifyCoreResponseProtocol
import org.codice.compliance.profiles.verifySsoProfile
import org.codice.security.sign.Decoder
import org.codice.security.sign.Decoder.InflationException
import org.codice.security.sign.Decoder.InflationException.InflErrorCode
import java.io.IOException

// todo once we support more bindings, Section 3.1.1: "if a SAML request message is accompanied by RelayState data,
// then the SAML responder MUST return its SAML protocol response using a binding that also supports a RelayState mechanism"
/**
 * Delegates the response to the correct POST or REDIRECT binding
 */
fun assertResponse(response: String, givenRelayState: Boolean) {
    if (response.contains("?")) assertRedirectResponse(response, givenRelayState)
    else assertPostResponse(response, givenRelayState)
}

fun assertRedirectResponse(response: String, givenRelayState: Boolean) {
    val parsedResponse = parseFinalRedirectResponse(response)
    val samlResponse = parsedResponse[SAML_RESPONSE]
    val samlEncoding = parsedResponse["SAMLEncoding"]
    val decodedMessage: String

    /**
     * A query string parameter named SAMLEncoding is reserved to identify the encoding mechanism used. If this
     * parameter is omitted, then the value is assumed to be urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE.
     */
    decodedMessage = if (samlEncoding == null || samlEncoding.equals("urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE")) {
        try {
            Decoder.decodeAndInflateRedirectMessage(samlResponse)
        } catch (e: InflationException) {
            when (e.inflErrorCode) {
                InflErrorCode.ERROR_DECODING -> throw SAMLComplianceException.create("SAMLBindings.3.4.4.1_b1")
                InflErrorCode.ERROR_INFLATING -> throw SAMLComplianceException.create("SAMLBindings.3.4.4.1_a1", "SAMLBindings.3.4.4.1")
                InflErrorCode.LINEFEED_OR_WHITESPACE -> throw SAMLComplianceException.create("SAMLBindings.3.4.4.1_a2")
                else -> throw SAMLComplianceException.create("SAMLBindings.3.4.4.1_a1", "SAMLBindings.3.4.4.1")
            }
        }
    } else "error"

    decodedMessage shouldNotBe null
    decodedMessage shouldNotBe "error"
    val responseDomElement = buildDom(decodedMessage)
    verifyCore(responseDomElement, ID)
    verifyCoreResponseProtocol(responseDomElement)
    verifySsoProfile(responseDomElement)
    verifyRedirect(responseDomElement, parsedResponse, givenRelayState)
}

fun assertPostResponse(response: String, givenRelayState: Boolean) {
    val parsedResponse = parseFinalPostResponse(response)
    val samlResponse = parsedResponse[SAML_RESPONSE]
    val decodedMessage: String
    try {
        decodedMessage = Decoder.decodePostMessage(samlResponse)
    } catch (e: IOException) {
        throw SAMLComplianceException.create("SAMLBindings.3.5.4")
    }

    decodedMessage shouldNotBe null
    val responseDomElement = buildDom(decodedMessage)
    verifyCore(responseDomElement, ID)
    verifyCoreResponseProtocol(responseDomElement)
    verifySsoProfile(responseDomElement)
    verifyPost(responseDomElement, parsedResponse, givenRelayState)
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
            it.startsWith(SAML_RESPONSE) -> parsedResponse.put(SAML_RESPONSE, it.replace("$SAML_RESPONSE=", ""))
            it.startsWith(RELAY_STATE) -> parsedResponse.put(RELAY_STATE, it.replace("$RELAY_STATE=", ""))
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
            it.startsWith(SAML_RESPONSE) -> parsedResponse.put(SAML_RESPONSE, it.replace("$SAML_RESPONSE=", ""))
            it.startsWith(SIG_ALG) -> parsedResponse.put(SIG_ALG, it.replace("$SIG_ALG=", ""))
            it.startsWith(SIGNATURE) -> parsedResponse.put(SIGNATURE, it.replace("$SIGNATURE=", ""))
            it.startsWith(RELAY_STATE) -> parsedResponse.put(RELAY_STATE, it.replace("$RELAY_STATE=", ""))
            it.startsWith("SAMLEncoding") -> parsedResponse["SAMLEncoding"] = it.replace("SAMLEncoding=", "")
        }
    }
    return parsedResponse
}