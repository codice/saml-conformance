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
package org.codice.compliance.verification.core.internal

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_2_2_3_a
import org.codice.compliance.SAMLCore_2_2_3_b
import org.codice.compliance.SAMLCore_2_3_3_a
import org.codice.compliance.SAMLCore_2_3_3_b
import org.codice.compliance.SAMLCore_2_3_3_c
import org.codice.compliance.SAMLCore_2_3_4_a
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.SAML_VERSION
import org.codice.compliance.verification.core.CommonDataTypeVerifier
import org.w3c.dom.Node

internal class AssertionsVerifier(val node: Node) {
    companion object {
        private const val ID = "ID"
        private const val VERSION = "Version"
        private const val ASSERTION = "Assertion"
        private const val ISSUE_INSTANT = "IssueInstant"
        private const val SAMLCore_2_3_3 = "SAMLCore.2.3.3"
    }

    fun verify() {
        verifyCoreAssertion()
        verifyEncryptedAssertion()
    }

    /**
     * Verify the <Assertion> Element against the Core Spec document
     * 2.3.3 Element <Assertion>
     */
    @Suppress("ComplexCondition")
    private fun verifyCoreAssertion() {
        node.allChildren(ASSERTION).forEach {
            if (it.attributes.getNamedItem(VERSION)?.textContent == null)
                throw SAMLComplianceException.createWithXmlPropertyReqMessage(SAMLCore_2_3_3,
                        property = VERSION,
                        parent = ASSERTION,
                        node = node)
            if (it.attributes.getNamedItem(VERSION).textContent != SAML_VERSION)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_2_3_3_a,
                        property = VERSION,
                        actual = it.attributes.getNamedItem(VERSION).textContent,
                        expected = SAML_VERSION,
                        node = node)

            if (it.attributes.getNamedItem(ID) == null)
                throw SAMLComplianceException.createWithXmlPropertyReqMessage(SAMLCore_2_3_3,
                        property = ID,
                        parent = ASSERTION,
                        node = node)
            CommonDataTypeVerifier.verifyIdValues(it.attributes.getNamedItem(ID), SAMLCore_2_3_3_b)

            if (it.attributes.getNamedItem(ISSUE_INSTANT) == null)
                throw SAMLComplianceException.createWithXmlPropertyReqMessage(SAMLCore_2_3_3,
                        property = ISSUE_INSTANT,
                        parent = ASSERTION,
                        node = node)
            CommonDataTypeVerifier.verifyTimeValues(it.attributes.getNamedItem(ISSUE_INSTANT),
                    SAMLCore_2_3_3_c)

            if (it.children("Issuer").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage(SAMLCore_2_3_3,
                        property = "Issuer",
                        parent = ASSERTION,
                        node = node)

            val statements = it.children("Statement")
            if (statements.any { it.attributes.getNamedItemNS(TestCommon.XSI, "type") == null })
                throw SAMLComplianceException.create(SAMLCore_2_2_3_a,
                        message = "Statement element found without a type.",
                        node = node)

            if (statements.isEmpty()
                    && it.children("AuthnStatement").isEmpty()
                    && it.children("AuthzDecisionStatement").isEmpty()
                    && it.children("AttributeStatement").isEmpty()
                    && it.children("Subject").isEmpty())
                throw SAMLComplianceException.create(SAMLCore_2_2_3_b,
                        message = "No Subject or Statement elements found.",
                        node = node)
        }
    }

    /**
     * Verify the <EncryptedAssertion> element against the Core Spec document
     * 2.3.4 Element <EncryptedAssertion>
     */
    private fun verifyEncryptedAssertion() {
        node.allChildren("EncryptedAssertion").forEach {
            val encryptedData = it.children("EncryptedData")
            if (encryptedData.isEmpty())
                throw SAMLComplianceException
                        .createWithXmlPropertyReqMessage("SAMLCore.2.3.4",
                                property = "EncryptedData",
                                parent = "EncryptedAssertion",
                                node = node)

            if (encryptedData.filter { it.attributes.getNamedItem("Type") != null }
                            .any { it.attributes.getNamedItem("Type").textContent !=
                                    TestCommon.ELEMENT })
                throw SAMLComplianceException.create(SAMLCore_2_3_4_a,
                        message = "Type attribute found with an incorrect value.",
                        node = node)
        }
    }
}
