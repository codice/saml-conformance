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

package org.codice.compliance.verification

import io.kotlintest.matchers.shouldNotBe
import org.apache.cxf.rs.security.saml.sso.SSOConstants.*
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.utils.TestCommon.Companion.ID
import org.codice.compliance.utils.TestCommon.Companion.buildDom
import org.codice.compliance.verification.binding.*
import org.codice.compliance.verification.core.CoreVerifier
import org.codice.compliance.verification.core.ResponseProtocolVerifier
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import org.codice.security.sign.Decoder
import org.codice.security.sign.Decoder.InflationException
import org.codice.security.sign.Decoder.InflationException.InflErrorCode
import org.w3c.dom.Node
import java.io.IOException

sealed class ResponseVerifier(val response: String, val givenRelayState: Boolean) {

    internal fun verifyResponse() {
        val parsedResponse = parseResponse(response)

        // Verifications from the Bindings document
        val decodedResponse = decodeResponse(parsedResponse)

        // Verifications from both the Core and Profiles document
        val responseDom = buildDomAndVerify(decodedResponse)

        // Verifications from the Bindings document
        val bindingVerifier = getBindingVerifier(responseDom, parsedResponse, givenRelayState)
        bindingVerifier.verifyBinding()
    }

    abstract protected fun parseResponse(rawResponse: String): Map<String, String>
    abstract protected fun decodeResponse(parsedResponse: Map<String, String>): String
    abstract protected fun getBindingVerifier(responseDom: Node, parsedResponse: Map<String, String>, givenRelayState: Boolean): BindingVerifier

    protected fun buildDomAndVerify(decodedMessage: String): Node {
        return buildDom(decodedMessage).apply {

            val coreVerifier = CoreVerifier(this)
            coreVerifier.verify()

            val responseProtocolVerifier = ResponseProtocolVerifier(this, ID)
            responseProtocolVerifier.verify()

            val singleSignOnProfileVerifier = SingleSignOnProfileVerifier(this)
            singleSignOnProfileVerifier.verify()
        }
    }
}

class RedirectResponseVerifier(response: String, givenRelayState: Boolean = false) : ResponseVerifier(response, givenRelayState) {
    /**
     * Parses a redirect idp response
     * @param - String response ordered in any order.
     * For example, "https://host:port/location?SAMLResponse=**SAMLResponse**&SigAlg=**SigAlg**&Signature=**Signature**
     * @return - A map from String key (Location, SAMLResponse, SigAlg, Signature, RelayState) to String value
     */
    override fun parseResponse(idpResponse: String): Map<String, String> {
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

    override fun decodeResponse(parsedResponse: Map<String, String>): String {
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
        } else throw UnsupportedOperationException("This test suite only supports DEFLATE encoding currently.")

        decodedMessage shouldNotBe null

        return decodedMessage
    }

    override fun getBindingVerifier(responseDom: Node, parsedResponse: Map<String, String>, givenRelayState: Boolean): BindingVerifier {
        return RedirectVerifier(responseDom, parsedResponse, givenRelayState)
    }
}

class PostResponseVerifier(response: String, givenRelayState: Boolean = false) : ResponseVerifier(response, givenRelayState) {
    /**
     * Parses a POST idp response
     * @param - String response ordered in any order.
     * For example, "SAMLResponse=**SAMLResponse**&RelayState=**RelayState**
     * @return - A map from String key (SAMLResponse, RelayState) to String value
     */
    override fun parseResponse(idpResponse: String): Map<String, String> {
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

    override fun decodeResponse(parsedResponse: Map<String, String>): String {
        val samlResponse = parsedResponse[SAML_RESPONSE]
        val decodedMessage: String
        try {
            decodedMessage = Decoder.decodePostMessage(samlResponse)
        } catch (e: IOException) {
            throw SAMLComplianceException.create("SAMLBindings.3.5.4")
        }

        decodedMessage shouldNotBe null

        return decodedMessage
    }

    override fun getBindingVerifier(responseDom: Node, parsedResponse: Map<String, String>, givenRelayState: Boolean): BindingVerifier {
        return PostVerifier(responseDom, parsedResponse, givenRelayState)
    }
}

// todo once we support more bindings, Section 3.1.1: "if a SAML request message is accompanied by RelayState data,
// then the SAML responder MUST return its SAML protocol response using a binding that also supports a RelayState mechanism"
/**
 * Delegates the response to the correct POST or REDIRECT binding
 */
fun verifyResponse(response: String, givenRelayState: Boolean) {
    val verifier =
            if (response.contains("?")) RedirectResponseVerifier(response, givenRelayState)
            else PostResponseVerifier(response, givenRelayState)
    verifier.verifyResponse()
}