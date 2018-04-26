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

import com.google.api.client.http.HttpStatusCodes
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.codice.compliance.SAMLBindings_3_1_2_1
import org.codice.compliance.SAMLBindings_3_4_3_a
import org.codice.compliance.SAMLBindings_3_4_3_b1
import org.codice.compliance.SAMLBindings_3_4_4_1
import org.codice.compliance.SAMLBindings_3_4_4_1_a
import org.codice.compliance.SAMLBindings_3_4_4_1_a1
import org.codice.compliance.SAMLBindings_3_4_4_1_a2
import org.codice.compliance.SAMLBindings_3_4_4_1_b1
import org.codice.compliance.SAMLBindings_3_4_4_1_c1
import org.codice.compliance.SAMLBindings_3_4_4_1_d1
import org.codice.compliance.SAMLBindings_3_4_4_1_d2
import org.codice.compliance.SAMLBindings_3_4_4_1_e
import org.codice.compliance.SAMLBindings_3_4_4_1_f1
import org.codice.compliance.SAMLBindings_3_4_4_1_f2
import org.codice.compliance.SAMLBindings_3_4_4_a
import org.codice.compliance.SAMLBindings_3_4_6_a
import org.codice.compliance.SAMLBindings_3_5_5_2_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.attributeNode
import org.codice.compliance.children
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon.Companion.DESTINATION
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.IDP_ERROR_RESPONSE_REMINDER_MESSAGE
import org.codice.compliance.utils.TestCommon.Companion.MAX_RELAY_STATE_LEN
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.compliance.utils.TestCommon.Companion.idpMetadata
import org.codice.compliance.utils.decorators.IdpRedirectResponseDecorator
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT
import org.codice.security.sign.Decoder
import org.codice.security.sign.Decoder.DecoderException.InflErrorCode.ERROR_BASE64_DECODING
import org.codice.security.sign.Decoder.DecoderException.InflErrorCode.ERROR_INFLATING
import org.codice.security.sign.Decoder.DecoderException.InflErrorCode.ERROR_URL_DECODING
import org.codice.security.sign.Decoder.DecoderException.InflErrorCode.LINEFEED_OR_WHITESPACE
import org.codice.security.sign.SimpleSign
import org.codice.security.sign.SimpleSign.SignatureException.SigErrorCode.INVALID_CERTIFICATE
import org.codice.security.sign.SimpleSign.SignatureException.SigErrorCode.INVALID_URI
import org.codice.security.sign.SimpleSign.SignatureException.SigErrorCode.SIGNATURE_NOT_PROVIDED
import org.codice.security.sign.SimpleSign.SignatureException.SigErrorCode.SIG_ALG_NOT_PROVIDED
import java.io.UnsupportedEncodingException
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

@Suppress("TooManyFunctions" /* At least at present, there is no value in refactoring */)
class RedirectBindingVerifier(private val response: IdpRedirectResponseDecorator)
    : BindingVerifier() {

    /** Verify the response for a redirect binding */
    override fun verify() {
        verifyHttpRedirectStatusCode()
        verifyNoNulls()
        decodeAndVerify()
        verifyNoXMLSig()
        if (response.isRelayStateGiven || response.relayState != null) {
            verifyRedirectRelayState()
        }
        response.signature?.let {
            verifyRedirectSignature()
            verifyRedirectDestination()
        }
    }

    /** Verify an error response (Negative path) */
    override fun verifyError() {
        verifyHttpRedirectStatusCodeErrorResponse()
        verifyNoNullsErrorResponse()
        decodeAndVerifyErrorResponse()
    }

    /**
     * Verifies the http status code of the response according to the redirect binding rules in the
     * binding spec
     * 3.4.6 Error Reporting
     */
    private fun verifyHttpRedirectStatusCode() {
        // TODO remove the 200 check when we change HTTP status code to expect 302/303
        if (response.httpStatusCode != HttpStatusCodes.STATUS_CODE_OK
                && response.httpStatusCode != HttpStatusCodes.STATUS_CODE_FOUND
                && response.httpStatusCode != HttpStatusCodes.STATUS_CODE_SEE_OTHER) {
            throw SAMLComplianceException.createWithPropertyMessage(
                    SAMLBindings_3_4_6_a,
                    property = "HTTP Status Code",
                    actual = response.httpStatusCode.toString(),
                    expected = "${HttpStatusCodes.STATUS_CODE_FOUND} or " +
                            HttpStatusCodes.STATUS_CODE_SEE_OTHER
            )
        }
    }

    /**
     * Verifies the http status code of the response according to the redirect binding rules in the
     * binding spec (Negative path)
     * 3.4.6 Error Reporting
     */
    private fun verifyHttpRedirectStatusCodeErrorResponse() {
        // TODO remove the 200 check when we change HTTP status code to expect 302/303
        if (response.httpStatusCode != HttpStatusCodes.STATUS_CODE_OK
                && response.httpStatusCode != HttpStatusCodes.STATUS_CODE_FOUND
                && response.httpStatusCode != HttpStatusCodes.STATUS_CODE_SEE_OTHER) {
            throw SAMLComplianceException.createWithPropertyMessage(
                    SAMLBindings_3_4_6_a,
                    property = "HTTP Status Code",
                    actual = response.httpStatusCode.toString(),
                    expected = "${HttpStatusCodes.STATUS_CODE_FOUND} or " +
                            HttpStatusCodes.STATUS_CODE_SEE_OTHER +
                            "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE"
            )
        }
    }

    /**
     * Verifies the presence of redirect parameters according to the redirect binding rules in the
     * binding spec
     * 3.4.4 Message Encoding
     */
    private fun verifyNoNulls() {
        with(response) {
            if (isUrlNull) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_4_a,
                        message = "Url not found.")
            }
            if (isPathNull) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_4_a,
                        message = "Path not found.")
            }
            if (isParametersNull) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_4_a,
                        message = "Parameters not found.")
            }
            if (samlResponse == null) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_4_a,
                        message = "SAMLResponse not found.")
            }
            if (isRelayStateGiven && relayState == null) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_3_b1,
                        message = "RelayState not found.")
            }
        }
    }

    /**
     * Verifies the presence of redirect parameters according to the redirect binding rules in the
     * binding spec (Negative path)
     * 3.4.4 Message Encoding
     */
    private fun verifyNoNullsErrorResponse() {
        with(response) {
            if (isUrlNull) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_4_a,
                        message = "Url not found." +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
            if (isPathNull) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_4_a,
                        message = "Path not found." +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
            if (isParametersNull) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_4_a,
                        message = "Parameters not found." +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
            if (samlResponse == null) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_4_a,
                        message = "SAMLResponse not found." +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
            if (isRelayStateGiven && relayState == null) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_4_3_b1,
                        message = "RelayState not found." +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
        }
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the redirect binding
     * rules in the binding spec
     * 3.4.4.1 Deflate Encoding
     */
    @Suppress("ComplexMethod" /* Complexity due to nested `when` is acceptable */)
    private fun decodeAndVerify() {
        val samlResponse = response.samlResponse
        val samlEncoding = response.samlEncoding
        val decodedMessage: String

        /**
         * A query string parameter named SAMLEncoding is reserved to identify the encoding
         * mechanism used. If this parameter is omitted, then the value is assumed to be
         * urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE.
         */
        decodedMessage = if (samlEncoding == null ||
                samlEncoding == "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE") {
            try {
                Decoder.decodeAndInflateRedirectMessage(samlResponse)
            } catch (e: Decoder.DecoderException) {
                when (e.inflErrorCode) {
                    ERROR_URL_DECODING ->
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_b1,
                                message = "Could not url decode the SAML response.",
                                cause = e)
                    ERROR_BASE64_DECODING ->
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_b1,
                                message = "Could not base64 decode the SAML response.",
                                cause = e)
                    ERROR_INFLATING -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a1,
                            SAMLBindings_3_4_4_1,
                            message = "Could not inflate the SAML response.",
                            cause = e)
                    LINEFEED_OR_WHITESPACE ->
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a2,
                                message = "There were linefeeds or whitespace in the SAML " +
                                        "response.",
                                cause = e)
                    else -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a,
                            SAMLBindings_3_4_4_1,
                            message = "Something went wrong with the SAML response.",
                            cause = e)
                }
            }
        } else throw UnsupportedOperationException("This test suite only supports DEFLATE " +
                "encoding currently.")

        decodedMessage.debugPrettyPrintXml("Decoded SAML Response")
        response.decodedSamlResponse = decodedMessage
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the redirect binding
     * rules in the binding spec (Negative path)
     * 3.4.4.1 Deflate Encoding
     */
    @Suppress("ComplexMethod" /* Complexity due to nested `when` is acceptable */)
    private fun decodeAndVerifyErrorResponse() {
        val samlResponse = response.samlResponse
        val samlEncoding = response.samlEncoding
        val decodedMessage: String

        /**
         * A query string parameter named SAMLEncoding is reserved to identify the encoding
         * mechanism used. If this parameter is omitted, then the value is assumed to be
         * urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE.
         */
        decodedMessage = if (samlEncoding == null ||
                samlEncoding.equals("urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE")) {
            try {
                Decoder.decodeAndInflateRedirectMessage(samlResponse)
            } catch (e: Decoder.DecoderException) {
                when (e.inflErrorCode) {
                    ERROR_URL_DECODING ->
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_b1,
                                message = "Could not url decode the SAML response." +
                                        "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                                cause = e)
                    ERROR_BASE64_DECODING ->
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_b1,
                                message = "Could not base64 decode the SAML response." +
                                        "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                                cause = e)
                    ERROR_INFLATING -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a1,
                            SAMLBindings_3_4_4_1,
                            message = "Could not inflate the SAML response." +
                                    "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                            cause = e)
                    LINEFEED_OR_WHITESPACE ->
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a2,
                                message = "There were linefeeds or whitespace in the SAML " +
                                        "response." +
                                        "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                                cause = e)
                    else -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a,
                            SAMLBindings_3_4_4_1,
                            message = "Something went wrong with the SAML response." +
                                    "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                            cause = e)
                }
            }
        } else throw UnsupportedOperationException("This test suite only supports DEFLATE " +
                "encoding currently.")

        decodedMessage.debugPrettyPrintXml("Decoded SAML Response")
        response.decodedSamlResponse = decodedMessage
    }

    /**
     * Verifies the redirect response has no XMLSig in the url according to the redirect binding
     * rules in the binding spec
     * 3.4.4.1 DEFLATE Encoding
     */
    private fun verifyNoXMLSig() {
        if (response.responseDom.children("Signature").isNotEmpty()) {
            throw SAMLComplianceException.create(SAMLBindings_3_4_4_1,
                    message = "Signature element found.",
                    node = response.responseDom)
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
                INVALID_CERTIFICATE -> throw SAMLComplianceException.create(SAMLBindings_3_1_2_1,
                        message = "The certificate was invalid.",
                        cause = e)
                SIG_ALG_NOT_PROVIDED ->
                    throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_d1,
                            message = "Signature Algorithm not found.",
                            cause = e)
                SIGNATURE_NOT_PROVIDED ->
                    throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_f2,
                            message = "Signature not found.",
                            cause = e)
                INVALID_URI -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_d2,
                        message = "The Signature algorithm named ${response.sigAlg} is unknown.",
                        cause = e)
                LINEFEED_OR_WHITESPACE ->
                    throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_f1,
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
        val isRelayStateGiven = response.isRelayStateGiven

        val decodedRelayState: String
        try {
            decodedRelayState = URLDecoder.decode(encodedRelayState, StandardCharsets.UTF_8.name())
        } catch (e: UnsupportedEncodingException) {
            throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_c1,
                    message = "RelayState could not be URL decoded.",
                    cause = e)
        }

        if (decodedRelayState.toByteArray().size > MAX_RELAY_STATE_LEN) {
            throw SAMLComplianceException.create(SAMLBindings_3_4_3_a,
                    message = "RelayState value of $decodedRelayState was longer than 80 bytes.")
        }

        if (isRelayStateGiven) {
            if (decodedRelayState != EXAMPLE_RELAY_STATE) {
                if (encodedRelayState == EXAMPLE_RELAY_STATE) {
                    throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_4_4_1_c1,
                            property = "RelayState",
                            actual = encodedRelayState)
                }
                throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_4_3_b1,
                        property = "RelayState",
                        actual = decodedRelayState,
                        expected = EXAMPLE_RELAY_STATE)
            }
        }
    }

    /**
     * Verifies the destination is correct according to the redirect binding rules in the binding
     * spec
     * 3.4.5.2 Security Considerations
     */
    private fun verifyRedirectDestination() {
        val destination = response.responseDom.attributeNode(DESTINATION)?.nodeValue
        val signatures = response.responseDom.recursiveChildren("Signature")

        if (signatures.isNotEmpty() && destination != acsUrl[HTTP_REDIRECT]) {
            throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_5_5_2_a,
                    property = DESTINATION,
                    actual = destination,
                    expected = acsUrl[HTTP_REDIRECT],
                    node = response.responseDom)
        }
    }
}
