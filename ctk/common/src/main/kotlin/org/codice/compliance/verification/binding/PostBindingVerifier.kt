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

import com.jayway.restassured.response.Response
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.codice.compliance.Common
import org.codice.compliance.SAMLBindings_3_5_4_a
import org.codice.compliance.SAMLBindings_3_5_5_2_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_4_1_4_5_a
import org.codice.compliance.attributeNode
import org.codice.compliance.children
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon.Companion.ASSERTION
import org.codice.compliance.utils.TestCommon.Companion.DESTINATION
import org.codice.compliance.utils.TestCommon.Companion.IDP_ERROR_RESPONSE_REMINDER_MESSAGE
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.sign.Decoder
import kotlin.test.assertNotNull

class PostBindingVerifier(override val response: Response) : BindingVerifier(response) {
    /** Verify the response for a post binding */
    override fun decodeAndVerify(): org.w3c.dom.Node {
        verifyHttpStatusCode(response.statusCode)
        val samlResponseString = PostFormVerifier(response, isRelayStateGiven).verifyAndParse()
        val samlResponseDom = decode(samlResponseString)
        verifyPostSSO(samlResponseDom)
        verifyPostDestination(samlResponseDom)
        return samlResponseDom
    }

    /** Verify an error response (Negative path) */
    override fun decodeAndVerifyError(): org.w3c.dom.Node {
        verifyHttpStatusCodeErrorResponse(response.statusCode)
        val samlResponseString = PostFormVerifier(response, isRelayStateGiven).verifyAndParseError()
        return decodeError(samlResponseString)
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the post binding rules
     * in the binding spec
     * 3.5.4 Message Encoding
     */
    private fun decode(response: String): org.w3c.dom.Node {
        val decodedMessage: String
        try {
            decodedMessage = Decoder.decodePostMessage(response)
        } catch (exception: Decoder.DecoderException) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    message = "The SAML response could not be base64 decoded.",
                    cause = exception)
        }

        assertNotNull(decodedMessage)
        decodedMessage.debugPrettyPrintXml("Decoded SAML Response")
        return Common.buildDom(decodedMessage)
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the post binding rules
     * in the binding spec (Negative path)
     * 3.5.4 Message Encoding
     */
    private fun decodeError(response: String): org.w3c.dom.Node {
        val decodedMessage: String
        try {
            decodedMessage = Decoder.decodePostMessage(response)
        } catch (exception: Decoder.DecoderException) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    message = "The SAML response could not be base64 decoded." +
                            "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                    cause = exception)
        }

        assertNotNull(decodedMessage)
        decodedMessage.debugPrettyPrintXml("Decoded SAML Response")
        return Common.buildDom(decodedMessage)
    }

    /**
     * Checks POST-specific rules from SSO profile spec
     * 4.1.4.5 POST-Specific Processing Rules
     */
    private fun verifyPostSSO(samlResponseDom: org.w3c.dom.Node) {
        if (samlResponseDom.children(SIGNATURE).isEmpty()
                || samlResponseDom.children(ASSERTION).any {
                    it.children(SIGNATURE).isEmpty()
                })
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_5_a,
                    message = "No digital signature found on the Response or Assertions.",
                    node = samlResponseDom)
    }

    /**
     * Verifies the destination is correct according to the post binding rules in the binding spec
     * 3.5.5.2 Security Considerations
     */
    private fun verifyPostDestination(samlResponseDom: org.w3c.dom.Node) {
        val destination = samlResponseDom.attributeNode(DESTINATION)?.nodeValue
        val signatures = samlResponseDom.recursiveChildren("Signature")

        if (signatures.isNotEmpty() && destination != acsUrl[HTTP_POST]) {
            throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_5_5_2_a,
                    property = DESTINATION,
                    actual = destination,
                    expected = acsUrl[HTTP_POST],
                    node = samlResponseDom)
        }
    }
}
