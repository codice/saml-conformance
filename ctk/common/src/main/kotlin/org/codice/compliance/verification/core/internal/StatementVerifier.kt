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

import org.apache.commons.lang3.StringUtils
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_2_7_2
import org.codice.compliance.SAMLCore_2_7_3
import org.codice.compliance.SAMLCore_2_7_3_1_1
import org.codice.compliance.SAMLCore_2_7_3_2_a
import org.codice.compliance.SAMLCore_2_7_4
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon
import org.w3c.dom.Node

@Suppress("StringLiteralDuplication")
internal class StatementVerifier(val node: Node) {

    fun verify() {
        verifyAuthnStatementAndAttributeStatement()
        verifyAttributeStatement()
        verifyAttribute()
        verifyEncryptedAttribute()
        verifyAuthzDecisionStatement()
        verifyAction()
    }

    /** 2.7.2 Element <AuthnStatement> **/
    private fun verifyAuthnStatementAndAttributeStatement() {
        if (node.allChildren("Assertion")
                        .filter { it.children("AuthnStatement").isNotEmpty() }
                        .any { it.children("Subject").isEmpty() })
            throw SAMLComplianceException.create(SAMLCore_2_7_2,
                    message = "An AuthnStatement was found without a Subject element.",
                    node = node)

        node.allChildren("AuthnStatement").forEach {
            if (it.attributes.getNamedItem("AuthnInstant") == null)
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.2.7.2",
                        "AuthnInstant",
                        "AuthnStatement",
                        node = node)

            if (it.children("AuthnContext").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.2.7.2",
                        "AuthnContext",
                        "AuthnStatement",
                        node = node)
        }
    }

    /** 2.7.3.2 Element <EncryptedAttribute> **/
    private fun verifyEncryptedAttribute() {
        node.allChildren("EncryptedAttribute").forEach {
            val encryptedData = it.children("EncryptedData")
            if (encryptedData.isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.2.7.3.2",
                        "EncryptedData",
                        "EncryptedAttribute",
                        node = node)

            if (encryptedData
                            .filter { it.attributes.getNamedItem("Type") != null }
                            .any { it.attributes.getNamedItem("Type").textContent !=
                                    TestCommon.ELEMENT })
                throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_2_7_3_2_a,
                        property = "Type",
                        actual = it.attributes.getNamedItem("Type").textContent,
                        expected = TestCommon.ELEMENT,
                        node = node)
            // todo - The encrypted content MUST contain an element that has a type of or derived
            // from AssertionType.
        }
    }

    /** 2.7.3.1 Element <Attribute> **/
    @Suppress("ComplexCondition")
    private fun verifyAttribute() {
        node.allChildren("Attribute").forEach {
            if (it.attributes.getNamedItem("Name") == null)
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.2.7.3.1",
                        "Name",
                        "Attribute",
                        node = node)

            val nameAttribute = it.attributes.getNamedItem("Name")
            val nameFormatAttribute = it.attributes.getNamedItem("NameFormat")
            val friendlyNameAttr = it.attributes.getNamedItem("FriendlyName")

            if ((nameAttribute != null && nameAttribute.textContent == null)
                    || (nameFormatAttribute != null && nameFormatAttribute.textContent == null)
                    || (friendlyNameAttr != null && friendlyNameAttr.textContent == null)) {
                verifyAttributeValue(it)
            }
        }
    }

    private fun verifyAttributeValue(it: Node) {
        it.children("AttributeValue").forEach {
            val nilAttribute = it.attributes.getNamedItemNS(TestCommon.XSI, "nil")?.textContent
            if (StringUtils.isNotBlank(it.textContent) ||
                    (nilAttribute != "true" && nilAttribute != "1"))
                throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_2_7_3_1_1,
                        property = "xsi:nil XML attribute",
                        actual = nilAttribute,
                        node = node)
        }
    }

    /** 2.7.3 Element <AttributeStatement> **/
    private fun verifyAttributeStatement() {
        if (node.allChildren("Assertion")
                        .filter { it.children("AttributeStatement").isNotEmpty() }
                        .any { it.children("Subject").isEmpty() })
            throw SAMLComplianceException.create(SAMLCore_2_7_3,
                    message = "An AttributeStatement was found without a Subject element.",
                    node = node)

        node.allChildren("AttributeStatement").forEach {
            if (it.children("Attribute").isEmpty() && it.children("EncryptedAttribute").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.2.7.3",
                        "Attribute or EncryptedAttribute",
                        "AttributeStatement",
                        node = node)
        }
    }

    /** 2.7.4 Element <AuthzDecisionStatement> **/
    private fun verifyAuthzDecisionStatement() {
        node.allChildren("Assertion").forEach {
            if (it.children("AuthzDecisionStatement").isNotEmpty()
                    && it.children("Subject").isEmpty())
                throw SAMLComplianceException.create(SAMLCore_2_7_4,
                        message = "No Subject element found.",
                        node = node)
        }

        node.allChildren("AuthzDecisionStatement").forEach {
            if (it.attributes.getNamedItem("Resource") == null)
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.2.7.4",
                        "Resource",
                        "AuthzDecisionStatement",
                        node = node)
            if (it.attributes.getNamedItem("Decision") == null)
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.2.7.4",
                        "Decision",
                        "AuthzDecisionStatement",
                        node = node)
            if (it.children("Action").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.2.7.4",
                        "Action",
                        "AuthzDecisionStatement",
                        node = node)
        }
    }

    /** 2.7.4.2 Element <Action> **/
    private fun verifyAction() {
        val actions = node.allChildren("Action")
        actions.forEach {
            if (it.attributes.getNamedItem("Namespace") == null)
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.2.7.4.2",
                        "Namespace",
                        "Action",
                        node = node)
        }
    }
}
