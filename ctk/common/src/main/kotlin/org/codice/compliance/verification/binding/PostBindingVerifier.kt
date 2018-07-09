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

import io.restassured.response.Response
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
import org.codice.compliance.utils.ASSERTION
import org.codice.compliance.utils.DESTINATION
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.utils.TestCommon.Companion.getServiceUrl
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.sign.Decoder
import org.w3c.dom.Node
import kotlin.test.assertNotNull

class PostBindingVerifier(httpResponse: Response) : BindingVerifier(httpResponse) {
    /** Verify the response for a post binding */
    override fun decodeAndVerify(): NodeDecorator {
        val samlResponseString =
                PostFormVerifier(httpResponse, isRelayStateGiven, isSamlRequest).verifyAndParse()
        val samlResponseDom = decode(samlResponseString)
        val nodeDecorator = NodeDecorator(samlResponseDom).apply {
            isSigned = verifyXmlSignatures(this)
        }
        verifyPostSSO(nodeDecorator)
        verifyPostDestination(nodeDecorator)
        return nodeDecorator
    }

    /** Verify an error response (Negative path) */
    override fun decodeAndVerifyError(): Node {
        val samlResponseString =
                PostFormVerifier(httpResponse, isRelayStateGiven, isSamlRequest)
                        .verifyAndParseError()
        val samlResponseDom = decode(samlResponseString)
        verifyXmlSignatures(samlResponseDom)
        return samlResponseDom
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the post binding rules
     * in the binding spec
     * 3.5.4 Message Encoding
     */
    private fun decode(response: String): Node {
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
     * Checks POST-specific rules from SSO profile spec
     * 4.1.4.5 POST-Specific Processing Rules
     */
    private fun verifyPostSSO(samlResponseDom: Node) {
        if (!samlResponseDom.nodeName.contains("Logout")
                && samlResponseDom.children(SIGNATURE).isEmpty()
                && samlResponseDom.children(ASSERTION).any {
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
    private fun verifyPostDestination(samlResponseDom: Node) {
        val destination = samlResponseDom.attributeNode(DESTINATION)?.nodeValue
        val signatures = samlResponseDom.recursiveChildren(SIGNATURE)

        val url = getServiceUrl(HTTP_POST, samlResponseDom)
        if (signatures.isNotEmpty() && destination != url) {
            throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_5_5_2_a,
                    property = DESTINATION,
                    actual = destination,
                    expected = url,
                    node = samlResponseDom)
        }
    }
}
