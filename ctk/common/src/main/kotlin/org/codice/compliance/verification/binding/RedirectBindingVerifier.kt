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
import io.restassured.response.Response
import org.apache.cxf.rs.security.saml.sso.SSOConstants.RELAY_STATE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIG_ALG
import org.codice.compliance.Common
import org.codice.compliance.SAMLBindings_3_1_2_1_a
import org.codice.compliance.SAMLBindings_3_4_3_a
import org.codice.compliance.SAMLBindings_3_4_3_b
import org.codice.compliance.SAMLBindings_3_4_4_1_a
import org.codice.compliance.SAMLBindings_3_4_4_1_b
import org.codice.compliance.SAMLBindings_3_4_4_1_c
import org.codice.compliance.SAMLBindings_3_4_4_1_d
import org.codice.compliance.SAMLBindings_3_4_4_1_e
import org.codice.compliance.SAMLBindings_3_4_4_1_f
import org.codice.compliance.SAMLBindings_3_4_4_1_g
import org.codice.compliance.SAMLBindings_3_4_4_a
import org.codice.compliance.SAMLBindings_3_4_4_b
import org.codice.compliance.SAMLBindings_3_4_6_a
import org.codice.compliance.SAMLBindings_3_5_5_2_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLGeneral_a
import org.codice.compliance.attributeNode
import org.codice.compliance.children
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.DESTINATION
import org.codice.compliance.utils.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.LOCATION
import org.codice.compliance.utils.MAX_RELAY_STATE_LEN
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.utils.SAML_ENCODING
import org.codice.compliance.utils.TestCommon.Companion.getServiceUrl
import org.codice.compliance.utils.TestCommon.Companion.idpMetadata
import org.codice.compliance.utils.TestCommon.Companion.logoutRequestRelayState
import org.codice.compliance.utils.sign.SimpleSign
import org.codice.compliance.utils.sign.SimpleSign.SignatureException.SigErrorCode.INVALID_CERTIFICATE
import org.codice.compliance.utils.sign.SimpleSign.SignatureException.SigErrorCode.INVALID_URI
import org.codice.compliance.utils.sign.SimpleSign.SignatureException.SigErrorCode.SIGNATURE_NOT_PROVIDED
import org.codice.compliance.utils.sign.SimpleSign.SignatureException.SigErrorCode.SIG_ALG_NOT_PROVIDED
import org.codice.compliance.verification.core.CommonDataTypeVerifier.Companion.verifyUriValue
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT
import org.codice.security.sign.Decoder
import org.codice.security.sign.Decoder.DecoderException.InflErrorCode.ERROR_BASE64_DECODING
import org.codice.security.sign.Decoder.DecoderException.InflErrorCode.ERROR_INFLATING
import org.codice.security.sign.Decoder.DecoderException.InflErrorCode.ERROR_URL_DECODING
import org.codice.security.sign.Decoder.DecoderException.InflErrorCode.LINEFEED_OR_WHITESPACE
import org.w3c.dom.Node
import java.io.UnsupportedEncodingException
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

@Suppress("TooManyFunctions" /* At least at present, there is no value in refactoring */)
class RedirectBindingVerifier(httpResponse: Response) : BindingVerifier(httpResponse) {

    /** Verify the response for a redirect binding */
    override fun decodeAndVerify(): NodeDecorator {
        verifyHttpRedirectStatusCode()
        val paramMap = verifyNoNullsAndParse()
        verifyRedirectRelayState(paramMap[RELAY_STATE])
        val samlResponseDom = decode(paramMap)
        verifyNoXMLSig(samlResponseDom)
        verifyXmlSignatures(samlResponseDom) // Should verify assertions signature
        val nodeDecorator = NodeDecorator(samlResponseDom)
        paramMap[SIGNATURE]?.let {
            verifyRedirectSignature(paramMap)
            verifyRedirectDestination(nodeDecorator)
            nodeDecorator.isSigned = true
        }

        return nodeDecorator
    }

    /** Verify an error response (Negative path) */
    override fun decodeAndVerifyError(): Node {
        verifyHttpRedirectStatusCode()
        val paramMap = verifyNoNullsAndParse()
        return decode(paramMap)
    }

    /**
     * Verifies the http status code of the response according to the redirect binding rules in the
     * binding spec
     * 3.4.6 Error Reporting
     */
    private fun verifyHttpRedirectStatusCode() {
        if (httpResponse.statusCode != HttpStatusCodes.STATUS_CODE_FOUND
                && httpResponse.statusCode != HttpStatusCodes.STATUS_CODE_SEE_OTHER) {
            throw SAMLComplianceException.createWithPropertyMessage(
                    SAMLBindings_3_4_6_a,
                    property = "HTTP Status Code",
                    actual = httpResponse.statusCode.toString(),
                    expected = "${HttpStatusCodes.STATUS_CODE_FOUND} or " +
                            HttpStatusCodes.STATUS_CODE_SEE_OTHER
            )
        }
    }

    /**
     * Verifies the presence of redirect parameters according to the redirect binding rules in the
     * binding spec
     * 3.4.4 Message Encoding
     */
    @Suppress("StringLiteralDuplication" /* Doesn't like the not found messages */)
    private fun verifyNoNullsAndParse(): Map<String, String> {
        val url = httpResponse.header(LOCATION) ?: throw SAMLComplianceException.create(
                SAMLBindings_3_4_4_b,
                message = "Url not found.")

        val splitUrl = url.split("?")

        splitUrl.getOrNull(0) ?: throw SAMLComplianceException.create(
                SAMLBindings_3_4_4_b,
                message = "Path not found.")

        val parameters = splitUrl.getOrNull(1) ?: throw SAMLComplianceException.create(
                SAMLBindings_3_4_4_b,
                message = "Parameters not found.")

        val paramMap = parameters.split("&")
                .map { s -> s.split("=") }
                .associate { s -> s[0] to s[1] }

        if (!isSamlRequest && paramMap[SAML_RESPONSE] == null)
            throw SAMLComplianceException.create(
                    SAMLBindings_3_4_4_b,
                    message = "$SAML_RESPONSE not found.")

        if (isSamlRequest && paramMap[SAML_REQUEST] == null)
            throw SAMLComplianceException.create(
                    SAMLBindings_3_4_4_b,
                    message = "$SAML_REQUEST not found.")

        if (isRelayStateGiven && paramMap[RELAY_STATE] == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_4_3_b,
                    message = "$RELAY_STATE not found.")
        }

        if (isSamlRequest)
            logoutRequestRelayState = paramMap[RELAY_STATE]

        return paramMap
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the redirect binding
     * rules in the binding spec
     * 3.4.4.1 Deflate Encoding
     */
    @Suppress("ComplexMethod" /* Complexity due to nested `when` is acceptable */)
    private fun decode(paramMap: Map<String, String>): Node {
        val message = paramMap[SAML_RESPONSE] ?: paramMap[SAML_REQUEST]
        // Need to url decode SAMLEncoding first to check the encoding method uri
        val samlEncoding = paramMap[SAML_ENCODING]?.let {
            try {
                URLDecoder.decode(it, StandardCharsets.UTF_8.name())
            } catch (e: UnsupportedEncodingException) {
                throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_c,
                        message = "Could not url decode the SAMLEncoding parameter.",
                        cause = e)
            }
        }
        samlEncoding?.let { verifyUriValue(it, SAMLBindings_3_4_4_a) }

        // A query string parameter named SAMLEncoding is reserved to identify the encoding
        // mechanism used. If this parameter is omitted, then the value is assumed to be
        // urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE.
        val decodedMessage = if (samlEncoding == null ||
                samlEncoding == "urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE") {
            try {
                Decoder.decodeAndInflateRedirectMessage(message)
            } catch (e: Decoder.DecoderException) {
                when (e.inflErrorCode) {
                    ERROR_URL_DECODING ->
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_c,
                                message = "Could not url decode the SAML response.",
                                cause = e)
                    ERROR_BASE64_DECODING ->
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_c,
                                message = "Could not base64 decode the SAML response.",
                                cause = e)
                    ERROR_INFLATING -> throw SAMLComplianceException.create(
                            SAMLBindings_3_4_4_1_b,
                            SAMLBindings_3_4_4_1_a,
                            message = "Could not inflate the SAML response.",
                            cause = e)
                    LINEFEED_OR_WHITESPACE ->
                        throw SAMLComplianceException.create(
                                SAMLBindings_3_4_4_1_b,
                                message = "There were linefeeds or whitespace in the SAML " +
                                        "response.",
                                cause = e)
                    else -> throw SAMLComplianceException.create(
                            SAMLBindings_3_4_4_1_b,
                            SAMLBindings_3_4_4_1_a,
                            message = "Something went wrong with the SAML response.",
                            cause = e)
                }
            }
        } else throw UnsupportedOperationException("This test suite only supports DEFLATE " +
                "encoding currently.")

        decodedMessage.debugPrettyPrintXml("Decoded SAML Response")
        return Common.buildDom(decodedMessage)
    }

    /**
     * Verifies the redirect response has no XMLSig in the url according to the redirect binding
     * rules in the binding spec
     * 3.4.4.1 DEFLATE Encoding
     */
    private fun verifyNoXMLSig(samlResponseDom: Node) {
        if (samlResponseDom.children("Signature").isNotEmpty()) {
            throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a,
                    message = "Signature element found.",
                    node = samlResponseDom)
        }
    }

    /**
     * Verifies the Signature and SigAlg according to the redirect binding rules in the binding spec
     * 3.4.4.1 DEFLATE Encoding
     */
    @Suppress("ComplexMethod" /* complexity in exception mapping to error is acceptable */)
    private fun verifyRedirectSignature(paramMap: Map<String, String>) {
        // Need to url decode SigAlg first to check the signature algorithm uri
        // It is guaranteed SigAlg can be url decoded because it already has been in decodeAndVerify
        val samlType = if (isSamlRequest) SAML_REQUEST else SAML_RESPONSE
        val sigAlg = paramMap[SIG_ALG]?.let {
            URLDecoder.decode(it, StandardCharsets.UTF_8.name())
        }
        verifyUriValue(sigAlg, SAMLBindings_3_4_4_1_e)

        try {
            if (!SimpleSign().validateSignature(
                            samlType,
                            paramMap[samlType],
                            paramMap[RELAY_STATE],
                            paramMap[SIGNATURE],
                            paramMap[SIG_ALG],
                            idpMetadata.signingCertificate)) {
                throw SAMLComplianceException.create(SAMLGeneral_a,
                        SAMLBindings_3_4_4_1_f,
                        message = "Invalid signature.")
            }
        } catch (e: SimpleSign.SignatureException) {
            when (e.errorCode) {
                INVALID_CERTIFICATE -> throw SAMLComplianceException.create(
                        SAMLBindings_3_1_2_1_a,
                        message = "The certificate was invalid.",
                        cause = e)
                SIG_ALG_NOT_PROVIDED ->
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_4_4_1_e,
                            message = "Signature Algorithm not found.",
                            cause = e)
                SIGNATURE_NOT_PROVIDED ->
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_4_4_1_g,
                            message = "Signature not found.",
                            cause = e)
                INVALID_URI -> throw SAMLComplianceException.create(
                        SAMLBindings_3_4_4_1_e,
                        message = "The Signature algorithm named ${paramMap[SIG_ALG]} is unknown.",
                        cause = e)
                LINEFEED_OR_WHITESPACE ->
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_4_4_1_g,
                            message = "Whitespace was found in the Signature.",
                            cause = e)
                else -> throw SAMLComplianceException.create(SAMLGeneral_a,
                        SAMLBindings_3_4_4_1_f,
                        message = "Invalid signature.",
                        cause = e)
            }
        }
    }

    /**
     * Verifies the relay state according to the redirect binding rules in the binding spec
     * 3.4.3 RelayState
     * 3.4.4.1 DEFLATE Encoding
     */
    private fun verifyRedirectRelayState(encodedRelayState: String?) {
        if (isRelayStateGiven || encodedRelayState != null) {
            val decodedRelayState: String
            try {
                decodedRelayState =
                        URLDecoder.decode(encodedRelayState, StandardCharsets.UTF_8.name())
            } catch (e: UnsupportedEncodingException) {
                throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_d,
                        message = "RelayState could not be URL decoded.",
                        cause = e)
            }

            if (decodedRelayState.toByteArray().size > MAX_RELAY_STATE_LEN) {
                throw SAMLComplianceException.create(SAMLBindings_3_4_3_a,
                        message = "RelayState value of $decodedRelayState was longer than 80 " +
                                "bytes.")
            }

            if (isRelayStateGiven && decodedRelayState != EXAMPLE_RELAY_STATE) {
                if (encodedRelayState == EXAMPLE_RELAY_STATE) {
                    throw SAMLComplianceException.createWithPropertyMessage(
                            SAMLBindings_3_4_4_1_d,
                            property = "RelayState",
                            actual = encodedRelayState)
                }
                throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_4_3_b,
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
    private fun verifyRedirectDestination(samlResponseDom: Node) {
        val destination = samlResponseDom.attributeNode(DESTINATION)?.nodeValue
        val signatures = samlResponseDom.recursiveChildren("Signature")

        val url = getServiceUrl(HTTP_REDIRECT, samlResponseDom)
        if (signatures.isNotEmpty() && destination != url) {
            throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_5_5_2_a,
                    property = DESTINATION,
                    actual = destination,
                    expected = url,
                    node = samlResponseDom)
        }
    }
}
