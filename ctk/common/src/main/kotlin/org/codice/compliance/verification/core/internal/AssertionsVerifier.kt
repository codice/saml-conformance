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
import org.codice.compliance.verification.core.verifyIdValues
import org.codice.compliance.verification.core.verifyTimeValues
import org.w3c.dom.Node

@Suppress("StringLiteralDuplication")
internal class AssertionsVerifier(val node: Node) {

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
        node.allChildren("Assertion").forEach {
            if (it.attributes.getNamedItem("Version")?.textContent == null)
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.2.3.3",
                        "Version",
                        "Assertion",
                        node = node)
            if (it.attributes.getNamedItem("Version").textContent != "2.0")
                throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_2_3_3_a,
                        property = "Version",
                        actual = it.attributes.getNamedItem("Version").textContent,
                        expected = "2.0",
                        node = node)

            if (it.attributes.getNamedItem("ID") == null)
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.2.3.3",
                        "ID",
                        "Assertion",
                        node = node)
            verifyIdValues(it.attributes.getNamedItem("ID"), SAMLCore_2_3_3_b)

            if (it.attributes.getNamedItem("IssueInstant") == null)
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.2.3.3",
                        "IssueInstant",
                        "Assertion",
                        node = node)
            verifyTimeValues(it.attributes.getNamedItem("IssueInstant"), SAMLCore_2_3_3_c)

            if (it.children("Issuer").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.2.3.3",
                        "Issuer",
                        "Assertion",
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
                                "EncryptedData",
                                "EncryptedAssertion",
                                node = node)

            if (encryptedData.filter { it.attributes.getNamedItem("Type") != null }
                            .any { it.attributes.getNamedItem("Type").textContent !=
                                    TestCommon.ELEMENT })
                throw SAMLComplianceException.create(SAMLCore_2_3_4_a,
                        message = "Type attribute found with an incorrect value.",
                        node = node)
            // todo - The encrypted content MUST contain an element that has a type of or derived
            // from AssertionType.
        }
    }
}
