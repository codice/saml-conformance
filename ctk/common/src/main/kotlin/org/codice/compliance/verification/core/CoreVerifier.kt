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
package org.codice.compliance.verification.core

import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_2_1_d
import org.codice.compliance.SAMLCore_5_4_1
import org.codice.compliance.SAMLCore_5_4_2_a
import org.codice.compliance.SAMLCore_5_4_2_b
import org.codice.compliance.SAMLCore_5_4_2_b1
import org.codice.compliance.SAMLCore_6_1_b
import org.codice.compliance.SAMLSpecRefMessage
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon.Companion.ELEMENT
import org.codice.compliance.utils.TestCommon.Companion.REQUESTER
import org.w3c.dom.Node

@Suppress("StringLiteralDuplication")
class CoreVerifier(val node: Node) {

    /**
     * Verifies that a response has the expected status code.
     * This should be called explicitly if an error is expected.
     *
     * @param samlErrorCode - The error code you wish to use for the SAMLComplianceException
     * @param expectedStatusCode - the uri of the expected status code.
     * For example, urn:oasis:names:tc:SAML:2.0:status:Requester.
     */
    fun verifyErrorStatusCode(samlErrorCode: SAMLSpecRefMessage, expectedStatusCode: String) {
        val status = node.children("Status")
        if (status.size != 1)
            throw SAMLComplianceException.createWithPropertyMessage(samlErrorCode,
                    property = "Status",
                    actual = "[]",
                    expected = "<Status>",
                    node = node)
        status[0].children("StatusCode").forEach {
            val code = it.attributes.getNamedItem("Value").textContent
            if (code != expectedStatusCode) {
                var exceptions = arrayOf(samlErrorCode)
                if (expectedStatusCode == REQUESTER)
                    exceptions = arrayOf(samlErrorCode, SAMLCore_3_2_1_d)

                @Suppress("SpreadOperator")
                throw SAMLComplianceException.createWithPropertyMessage(*exceptions,
                        property = "Status Code",
                        actual = code,
                        expected = expectedStatusCode,
                        node = status[0])
            }
        }
    }

    /**
     * Verify response against the Core Spec document
     */
    fun verify() {
        verifyCommonDataType(node)

        SamlAssertionsVerifier(node).verify()
        SamlIdentifiersVerifier(node).verify()

        verifySignatureSyntaxAndProcessing(node)
        verifyGeneralConsiderations(node)
    }

    /**
     * Verify signatures against the Core Spec document
     *
     * 5 SAML and XML Signature Syntax and Processing
     * 5.4.1 Signing Formats and Algorithms
     */
    private fun verifySignatureSyntaxAndProcessing(node: Node) {
        node.children("Assertion").forEach {
            val signatures = it.children(SIGNATURE)
            if (signatures.isEmpty())
                throw SAMLComplianceException.create(SAMLCore_5_4_1,
                        message = "Signature not found.",
                        node = node)

            if (it.attributes.getNamedItem("ID") == null)
                throw SAMLComplianceException.create(SAMLCore_5_4_2_a,
                        message = "ID not found.",
                        node = node)

            signatures.forEach {
                val references = it.allChildren("Reference")
                if (references.size != 1)
                    throw SAMLComplianceException.create(SAMLCore_5_4_2_b1,
                            message = "${references.size} Reference elements were found.",
                            node = node)

                val uriValue = references[0].attributes?.getNamedItem("URI")?.textContent
                val formattedId = "#" + it.parentNode?.attributes?.getNamedItem("ID")?.textContent
                if (uriValue != formattedId)
                    throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_5_4_2_b,
                            property = "URI",
                            actual = uriValue,
                            expected = formattedId,
                            node = node)
            }
        }
    }

    private fun verifyGeneralConsiderations(node: Node) {
        // todo - Encrypted data and [E30]zero or more encrypted keys MUST replace the plaintext
        // information in the same location within the XML instance.

        val elements = mutableListOf<Node>()
        elements.addAll(node.children("Assertion"))
        elements.addAll(node.children("BaseID"))
        elements.addAll(node.children("NameID"))
        elements.addAll(node.children("Attribute"))

        elements.forEach {
            val encryptedDataNode = it.allChildren("EncryptedData")

            if (encryptedDataNode.isNotEmpty()) {
                val encryptedData = encryptedDataNode
                        .get(0)
                        .attributes
                        .getNamedItem("EncryptedData")
                        .textContent
                if (encryptedData != ELEMENT)
                    throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_6_1_b,
                            property = "EncryptedData",
                            actual = encryptedData,
                            expected = ELEMENT,
                            node = node)
            }
        }
    }
}
