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
package org.codice.compliance.verification.binding

import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLSpecRefMessage.*
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.MAX_RELAYSTATE_LEN
import org.codice.compliance.utils.TestCommon.Companion.idpMetadata
import org.codice.compliance.utils.decorators.IdpRedirectResponseDecorator
import org.codice.security.sign.Decoder
import org.codice.security.sign.Decoder.DecoderException.InflErrorCode.*
import org.codice.security.sign.SimpleSign
import org.codice.security.sign.SimpleSign.SignatureException.SigErrorCode
import java.io.UnsupportedEncodingException
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

class RedirectBindingVerifier(private val response: IdpRedirectResponseDecorator) {
    /**
     * Verify the response for a redirect binding
     */
    fun verify() {
        decodeAndVerify()
        verifyRequestParam()
        verifyNoXMLSig()
        verifyRedirectRelayState()
        response.signature?.let {
            verifyRedirectSignature()
            verifyRedirectDestination()
        }
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the redirect binding rules in the binding spec
     * 3.4.4.1 Deflate Encoding
     */
    @Suppress("ComplexMethod" /* Complexity due to nested `when` is acceptable */)
    private fun decodeAndVerify() {
        val samlResponse = response.samlResponse
        val samlEncoding = response.samlEncoding
        val decodedMessage: String

        /**
         * A query string parameter named SAMLEncoding is reserved to identify the encoding mechanism used. If this
         * parameter is omitted, then the value is assumed to be urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE.
         */
        decodedMessage = if (samlEncoding == null || samlEncoding.equals("urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE")) {
            try {
                Decoder.decodeAndInflateRedirectMessage(samlResponse)
            } catch (e: Decoder.DecoderException) {
                when (e.inflErrorCode) {
                    ERROR_URL_DECODING -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_b1,
                            message = "Could not url decode the SAML response.",
                            cause = e)
                    ERROR_BASE64_DECODING -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_b1,
                            message = "Could not base64 decode the SAML response.",
                            cause = e)
                    ERROR_INFLATING -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a1, SAMLBindings_3_4_4_1,
                            message = "Could not inflate the SAML response.",
                            cause = e)
                    LINEFEED_OR_WHITESPACE -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a2,
                            message = "There were linefeeds or whitespace in the SAML response.",
                            cause = e)
                    else -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a, SAMLBindings_3_4_4_1,
                            message = "Something went wrong with the SAML response.",
                            cause = e)
                }
            }
        } else throw UnsupportedOperationException("This test suite only supports DEFLATE encoding currently.")

        response.decodedSamlResponse = decodedMessage
    }

    /**
     * Verifies the redirect response has a SAMLResponse query param according to the redirect binding rules in the
     * binding spec
     * 3.4.4.1 DEFLATE Encoding
     */
    private fun verifyRequestParam() {
        if (response.samlResponse == null) {
            throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_b2, message = "No SAMLResponse found.")
        }
    }

    /**
     * Verifies the redirect response has no XMLSig in the url according to the redirect binding rules in the binding
     * spec
     * 3.4.4.1 DEFLATE Encoding
     */
    private fun verifyNoXMLSig() {
        if (response.responseDom.children("Signature").isNotEmpty()) {
            throw SAMLComplianceException.create(SAMLBindings_3_4_4_1, message = "Signature element found.")
        }
    }

    /**
     * Verifies the Signature and SigAlg according to the redirect binding rules in the binding spec
     * 3.4.4.1 DEFLATE Encoding
     */
    @Suppress("ComplexMethod" /* complexity in exception mapping to error is acceptable */)
    private fun verifyRedirectSignature() {
        try {
            if (!SimpleSign().validateSignature(
                            SAML_RESPONSE,
                            response.samlResponse,
                            response.relayState,
                            response.signature,
                            response.sigAlg,
                            idpMetadata.signingCertificate)) {
                throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_e,
                        message = "Signature does not match payload.")
            }
        } catch (e: SimpleSign.SignatureException) {
            when (e.errorCode) {
                SigErrorCode.INVALID_CERTIFICATE -> throw SAMLComplianceException.create(SAMLBindings_3_1_2_1,
                        message = "The certificate was invalid.",
                        cause = e)
                SigErrorCode.SIG_ALG_NOT_PROVIDED -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_d1,
                        message = "Signature Algorithm not found.",
                        cause = e)
                SigErrorCode.SIGNATURE_NOT_PROVIDED -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_f2,
                        message = "Signature not found.",
                        cause = e)
                SigErrorCode.INVALID_URI -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_d2,
                        message = "The Signature algorithm named ${response.sigAlg} is unknown.",
                        cause = e)
                SigErrorCode.LINEFEED_OR_WHITESPACE -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_f1,
                        message = "Whitespace was found in the Signature.",
                        cause = e)
                else -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_e,
                        message = "Signature does not match payload.",
                        cause = e)
            }
        }
    }

    /**
     * Verifies the relay state according to the redirect binding rules in the binding spec
     * 3.4.3 RelayState
     * 3.4.4.1 DEFLATE Encoding
     */
    private fun verifyRedirectRelayState() {
        val encodedRelayState = response.relayState
        val givenRelayState = response.isRelayStateGiven

        if (encodedRelayState == null) {
            if (givenRelayState) {
                throw SAMLComplianceException.create(SAMLBindings_3_4_3_b1, message = "RelayState not found.")
            }
            return
        }

        val decodedRelayState: String
        try {
            decodedRelayState = URLDecoder.decode(encodedRelayState, StandardCharsets.UTF_8.name())
        } catch (e: UnsupportedEncodingException) {
            throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_c1,
                    message = "RelayState could not be URL decoded.",
                    cause = e)
        }

        if (decodedRelayState.toByteArray().size > MAX_RELAYSTATE_LEN) {
            throw SAMLComplianceException.create(SAMLBindings_3_4_3_a,
                    message = "RelayState value of $decodedRelayState was longer than 80 bytes.")
        }

        if (givenRelayState) {
            if (decodedRelayState != EXAMPLE_RELAY_STATE) {
                if (encodedRelayState == EXAMPLE_RELAY_STATE) {
                    throw SAMLComplianceException.createWithPropertyInvalidMessage(SAMLBindings_3_4_4_1_c1,
                            "RelayState",
                            encodedRelayState)
                }
                throw SAMLComplianceException.createWithPropertyNotEqualMessage(SAMLBindings_3_4_3_b1,
                        "RelayState",
                        decodedRelayState,
                        EXAMPLE_RELAY_STATE)
            }
        }
    }

    /**
     * Verifies the destination is correct according to the redirect binding rules in the binding spec
     * 3.4.5.2 Security Considerations
     */
    private fun verifyRedirectDestination() {
        val destination = response.responseDom.attributes.getNamedItem("Destination")?.nodeValue
        val signatures = response.responseDom.allChildren("Signature")

        if (signatures.isNotEmpty() && destination != TestCommon.ACS_URL) {
            throw SAMLComplianceException.createWithPropertyNotEqualMessage(
                    SAMLBindings_3_5_5_2_a,
                    "Destination",
                    destination,
                    TestCommon.ACS_URL)
        }
    }
}
