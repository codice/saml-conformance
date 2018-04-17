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

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCoreRefMessage
import org.codice.compliance.SAMLCore_3_2_1_d
import org.codice.compliance.SAMLCore_SamlExtensions
import org.codice.compliance.SAMLSpecRefMessage
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.REQUESTER
import org.codice.compliance.verification.core.CommonDataTypeVerifier.Companion.verifyCommonDataType
import org.codice.compliance.utils.schema.SchemaValidator
import org.w3c.dom.Attr
import org.w3c.dom.Element
import org.w3c.dom.Node
import java.time.Instant

class CoreVerifier(val node: Node) {
    companion object {
        private const val ENCRYPTED_DATA = "EncryptedData"

        /**
         * Verify SAML extension attributes or elements against the Core Spec document
         *
         * 2.4.1.2 Element <SubjectConfirmationData>
         * 2.7.3.1 Element <Attribute>
         * 3.2.1 Complex Type RequestAbstractType
         * 3.2.2 Complex Type StatusResponseType
         */
        internal fun verifySamlExtensions(nodes: List<Node>,
                                          expectedSamlNames: List<String>) {
            nodes.forEach {
                if (isNullNamespace(it) || (isSamlNamespace(it)
                                && !expectedSamlNames.contains(it.localName))) {
                    throw SAMLComplianceException.create(SAMLCore_SamlExtensions,
                            message = "An invalid SAML extension was found.",
                            node = it)
                }
            }
        }

        private fun isNullNamespace(node: Node): Boolean {
            return with(node) {
                when (this) {
                    is Attr -> namespaceURI == null && ownerElement.namespaceURI == null
                    is Element -> namespaceURI == null
                    else -> throw UnknownError("Unknown Node type found")
                }
            }
        }

        private fun isSamlNamespace(node: Node): Boolean {
            return with(node) {
                when (this) {
                    is Attr -> {
                        namespaceURI == TestCommon.SAML_NAMESPACE
                                || ownerElement.namespaceURI == TestCommon.SAML_NAMESPACE
                    }
                    is Element -> namespaceURI == TestCommon.SAML_NAMESPACE
                    else -> throw UnknownError("Unknown Node type found")
                }
            }
        }

        /**
         * Checks the values of NotBefore and NotOnOrAfter attributes and verifies
         * that the value of NotBefore is less than the value for NotOnOrAfter.
         */
        internal fun validateTimeWindow(node: Node, samlCode: SAMLCoreRefMessage) {
            val notBefore = node.attributes?.getNamedItem("NotBefore")?.apply {
                CommonDataTypeVerifier.verifyDateTimeValues(this)
            }

            val notOnOrAfter = node.attributes?.getNamedItem("NotOnOrAfter")?.apply {
                CommonDataTypeVerifier.verifyDateTimeValues(this)
            }

            if (notBefore == null || notOnOrAfter == null) return

            val notBeforeValue = Instant.parse(notBefore.textContent)
            val notOnOrAfterValue = Instant.parse(notOnOrAfter.textContent)
            if (notBeforeValue.isAfter(notOnOrAfterValue))
                throw SAMLComplianceException.create(samlCode,
                        message = "NotBefore element with value $notBeforeValue is not less " +
                                "than NotOnOrAfter element with value $notOnOrAfterValue.",
                        node = node)
        }
    }

    /**
     * Verify response against the Core Spec document
     */
    fun verify() {
        SchemaValidator.validateSAMLMessage(node)
        verifyCommonDataType(node)
        SamlAssertionsVerifier(node).verify()
        SignatureSyntaxAndProcessingVerifier(node).verify()
        SamlDefinedIdentifiersVerifier(node).verify()
    }

    /**
     * Verifies that a response has the expected status code.
     * This should be called explicitly if an error is expected.
     *
     * @param samlErrorCode - The error code you wish to use for the SAMLComplianceException
     * @param expectedStatusCode - the uri of the expected status code.
     * For example, urn:oasis:names:tc:SAML:2.0:status:Requester.
     */
    fun verifyErrorStatusCode(samlErrorCode: SAMLSpecRefMessage, expectedStatusCode: String) {
        SchemaValidator.validateSAMLMessage(node)
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
}
