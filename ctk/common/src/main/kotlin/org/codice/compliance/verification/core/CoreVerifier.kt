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

import de.jupf.staticlog.Log
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCoreRefMessage
import org.codice.compliance.SAMLCore_3_2_1_d
import org.codice.compliance.SAMLCore_3_2_2_2_a
import org.codice.compliance.SAMLSpecRefMessage
import org.codice.compliance.attributeNode
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.prettyPrintXml
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.utils.REQUESTER
import org.codice.compliance.utils.STATUS
import org.codice.compliance.utils.STATUS_CODE
import org.codice.compliance.utils.schema.SchemaValidator
import org.codice.compliance.utils.topLevelStatusCodes
import org.codice.compliance.verification.core.CommonDataTypeVerifier.Companion.verifyCommonDataType
import org.w3c.dom.Node
import java.time.Instant

abstract class CoreVerifier(private val samlNode: NodeDecorator) {
    companion object {
        /**
         * Verifies that a response has the expected status code.
         * This should be called explicitly if an error is expected.
         *
         * @param samlErrorCodes - The error code(s) you wish to use for the SAMLComplianceException
         * @param expectedStatusCode - the uri of the expected status code.
         * For example, urn:oasis:names:tc:SAML:2.0:status:Requester.
         */
        @Suppress("SpreadOperator")
        fun verifyErrorStatusCodes(node: Node, vararg samlErrorCodes: SAMLSpecRefMessage,
                                   expectedStatusCode: String) {
            SchemaValidator.validateSAMLMessage(node)

            val statusCode = node.children(STATUS)
                    .firstOrNull()
                    ?.children(STATUS_CODE)
                    ?.firstOrNull()
                    ?.attributeText("Value")

            if (!topLevelStatusCodes.contains(statusCode))
                throw SAMLComplianceException.create(SAMLCore_3_2_2_2_a,
                        message = "The first <StatusCode> of $statusCode is not a top level SAML " +
                                "status code.",
                        node = node)

            if (statusCode != expectedStatusCode) {
                val exceptions =
                        if (expectedStatusCode == REQUESTER)
                            arrayOf(*samlErrorCodes, SAMLCore_3_2_1_d)
                        else
                            arrayOf(*samlErrorCodes)
                throw SAMLComplianceException.createWithPropertyMessage(*exceptions,
                        property = "Status Code",
                        actual = statusCode,
                        expected = expectedStatusCode,
                        node = node)
            }
        }

        /**
         * Checks the values of NotBefore and NotOnOrAfter attributes and verifies
         * that the value of NotBefore is less than the value for NotOnOrAfter.
         */
        internal fun validateTimeWindow(node: Node, samlCode: SAMLCoreRefMessage) {
            val notBefore = node.attributeNode("NotBefore")?.apply {
                CommonDataTypeVerifier.verifyDateTimeValue(this)
            }

            val notOnOrAfter = node.attributeNode("NotOnOrAfter")?.apply {
                CommonDataTypeVerifier.verifyDateTimeValue(this)
            }

            if (notBefore == null || notOnOrAfter == null) return

            val notBeforeValue = Instant.parse(notBefore.textContent)
            val notOnOrAfterValue = Instant.parse(notOnOrAfter.textContent)
            if (notBeforeValue == notOnOrAfterValue || notBeforeValue.isAfter(notOnOrAfterValue))
                throw SAMLComplianceException.create(samlCode,
                        message = "NotBefore element with value $notBeforeValue is not less " +
                                "than NotOnOrAfter element with value $notOnOrAfterValue.",
                        node = node)
        }

        private fun retrieveCurrentEncryptedElements(responseDom: Node): List<Node> {
            return responseDom.recursiveChildren("EncryptedAssertion") +
                    responseDom.recursiveChildren("EncryptedAttribute") +
                    responseDom.recursiveChildren("EncryptedID")
        }
    }

    private val node = samlNode.node

    /**
     * Verify response against the Core Spec document
     */
    open fun verify() {
        preProcess()
        verifyCommonDataType(node)
        SamlAssertionsVerifier(node).verify()
        SamlVersioningVerifier(node).verify()
        SignatureSyntaxAndProcessingVerifier(node).verify()
        SamlDefinedIdentifiersVerifier(node).verify()
    }

    open fun verifyEncryptedElements() {
    }

    private fun preProcess(encVerifier: EncryptionVerifier = EncryptionVerifier()) {
        val encElements = retrieveCurrentEncryptedElements(node)
        if (encElements.isEmpty()) {
            Log.debugWithSupplier {
                "Decrypted SAML Response:\n\n ${node.prettyPrintXml()}"
            }
            return
        }

        Log.debugWithSupplier {
            "Starting a pass of decryption and schema validation" +
                    " on the SAML Response."
        }

        SchemaValidator.validateSAMLMessage(node)
        verifyEncryptedElements()

        if (encElements.any { it.localName == "EncryptedAssertion" })
            samlNode.hasEncryptedAssertion = true

        encVerifier.verifyAndDecryptElements(encElements)
        preProcess(encVerifier)
    }
}
