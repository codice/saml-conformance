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

import org.apache.commons.lang3.StringUtils
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.w3c.dom.Node
import java.time.Instant

class SamlAssertionsVerifier(val node: Node) {
    /**
     * Verify assertions against the Core Spec document
     * 2 SAML Assertions
     */
    fun verify() {
        verifyEncryptedId()
        verifyCoreAssertion()
        verifyEncryptedAssertion()
        verifySubjectElements()
        verifyConditions()
        verifyAuthnStatementAndAttributeStatement()
        verifyAttributeElements()
        verifyAuthzDecisionStatementAndAction()
    }

    /**
     * Verify the <EncryptedId> Element against the Core Spec document
     * 2.2.4 Element <EncryptedID>
     */
    private fun verifyEncryptedId() {
        node.allChildren("EncryptedID").forEach {
            val encryptedData = it.children("EncryptedData")
            if (encryptedData.isEmpty()) throw SAMLComplianceException
                    .createWithReqMessage("SAMLCore.2.2.4", "EncryptedData", "EncryptedId")

            if (encryptedData
                            .filter { it.attributes.getNamedItem("Type") != null }
                            .any { it.attributes.getNamedItem("Type").textContent != "http://www.w3.org/2001/04/xmlenc#Element" })
                throw SAMLComplianceException.create("SAMLCore.2.2.4")
            // todo - For The encrypted content MUST contain an element that has a type of NameIDType or AssertionType,
            // or a type that is derived from BaseIDAbstractType, NameIDType, or AssertionType.
        }
        // todo - Encrypted identifiers are intended as a privacy protection mechanism when the plain-text value passes through an intermediary.
        // As such, the ciphertext MUST be unique to any given encryption operation. For more on such issues, see [XMLEnc] Section 6.3.
    }

    /**
     * Verify the <Assertion> Element against the Core Spec document
     * 2.3.3 Element <Assertion>
     */
    private fun verifyCoreAssertion() {
        node.allChildren("Assertion").forEach {
            if (it.attributes.getNamedItem("Version")?.textContent == null)
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.3.3", "Version", "Assertion")
            if (it.attributes.getNamedItem("Version").textContent != "2.0")
                throw SAMLComplianceException.create("SAMLCore.2.3.3_a")

            if (it.attributes.getNamedItem("ID") == null)
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.3.3", "ID", "Assertion")
            verifyIdValues(it.attributes.getNamedItem("ID"), "SAMLCore.2.3.3_b")

            if (it.attributes.getNamedItem("IssueInstant") == null)
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.3.3", "IssueInstant", "Assertion")
            verifyTimeValues(it.attributes.getNamedItem("IssueInstant"), "SAMLCore.2.3.3_c")

            if (it.children("Issuer").isEmpty())
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.3.3", "Issuer", "Assertion")

            val statements = it.children("Statement")
            if (statements.any { it.attributes.getNamedItemNS("http://www.w3.org/2001/XMLSchema-instance", "type") == null })
                throw SAMLComplianceException.create("SAMLCore.2.2.3_a")

            if (statements.isEmpty()
                    && it.children("AuthnStatement").isEmpty()
                    && it.children("AuthzDecisionStatement").isEmpty()
                    && it.children("AttributeStatement").isEmpty()
                    && it.children("Subject").isEmpty())
                throw SAMLComplianceException.create("SAMLCore.2.2.3_b")
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
                        .createWithReqMessage("SAMLCore.2.3.4", "EncryptedData", "EncryptedAssertion")

            if (encryptedData
                            .filter { it.attributes.getNamedItem("Type") != null }
                            .any { it.attributes.getNamedItem("Type").textContent != "http://www.w3.org/2001/04/xmlenc#Element" })
                throw SAMLComplianceException.create("SAMLCore.2.3.4")
            // todo - The encrypted content MUST contain an element that has a type of or derived from AssertionType.
        }
    }

    /**
     * Verify subject elements against the Core Spec
     * 2.4.1.1 Element <SubjectConfirmation>
     * 2.4.1.2 Element <SubjectConfirmationData>
     * 2.4.1.3 Complex Type KeyInfoConfirmationDataType
     */
    private fun verifySubjectElements() {
        // SubjectConfirmation
        if (node.allChildren("SubjectConfirmation")
                        .any { it.attributes.getNamedItem("Method") == null })
            throw SAMLComplianceException
                    .createWithReqMessage("SAMLCore.2.4.1.1", "Method", "SubjectConfirmation")

        // SubjectConfirmationData
        node.allChildren("SubjectConfirmationData").forEach {
            // todo - SAML extensions MUST NOT add local (non-namespace-qualified) XML attributes or XML attributes qualified by a SAML-defined
            // namespace to the SubjectConfirmationDataType complex type or a derivation of it; such attributes are reserved for future maintenance
            // and enhancement of SAML itself.

            val notBefore = it.attributes.getNamedItem("NotBefore")
            val notOnOrAfter = it.attributes.getNamedItem("NotOnOrAfter")
            if (notBefore != null
                    && notOnOrAfter != null
                    && Instant.parse(notBefore.textContent).isAfter(Instant.parse(notOnOrAfter.textContent)))
                throw SAMLComplianceException.create("SAMLCore.2.4.1.2_a")

            // KeyInfoConfirmationDataType
            // todo - verify correctness
            if (it.parentNode.attributes
                            ?.getNamedItemNS("http://www.w3.org/2001/XMLSchema-instance", "type")
                            ?.textContent?.contains("KeyInfoConfirmationDataType") == true
                    && it.children("KeyInfo").any { it.childNodes.length > 1 })
                throw SAMLComplianceException.create("SAMLCore.2.4.1.3_a")
        }
    }


    /**
     * Verify the <Conditions> element against the Core Spec
     * 2.5.1 Element <Conditions>
     * 2.5.1.2 Attributes NotBefore and NotOnOrAfter
     * 2.5.1.5 Element <OneTimeUse>
     * 2.5.1.6 Element <ProxyRestriction>
     */
    private fun verifyConditions() {
        node.allChildren("Conditions").forEach {
            if (it.children("Condition")
                            .any { it.attributes.getNamedItemNS("http://www.w3.org/2001/XMLSchemainstance", "type") == null })
                throw SAMLComplianceException.create("SAMLCore.2.5.1_a")

            if (it.children("OneTimeUse").size > 1)
                throw SAMLComplianceException.create("SAMLCore.2.5.1_b", "SAMLCore.2.5.1.5_a")

            val proxyRestrictions = it.children("ProxyRestriction")
            if (proxyRestrictions.isNotEmpty()) {
                if (proxyRestrictions.size > 1)
                    throw SAMLComplianceException.create("SAMLCore.2.5.1_c, SAMLCore.2.5.1.6_b")
                val audiences = mutableListOf<String>()
                proxyRestrictions.forEach {
                    it.children("Audience").forEach {
                        audiences.add(it.textContent)
                    }
                }

                // todo - verify this section
                node.allChildren("AudienceRestriction").forEach {
                    if (it.childNodes.length == 0)
                        throw SAMLComplianceException.create("SAMLCore.2.5.1.6_a")
                    it.children("Audience").forEach {
                        if (!audiences.contains(it.textContent))
                            throw SAMLComplianceException.create("SAMLCore.2.5.1.6_a")
                    }
                }
            }

            val notBefore = it.attributes.getNamedItem("NotBefore")
            val notOnOrAfter = it.attributes.getNamedItem("NotOnOrAfter")
            if (notBefore != null
                    && notOnOrAfter != null
                    && Instant.parse(notBefore.textContent).isAfter(Instant.parse(notOnOrAfter.textContent)))
                throw SAMLComplianceException.create("SAMLCore.2.5.1.2")
        }
    }

    /**
     * Verify the <AuthnStatement> element against the Core Spec
     * 2.7.2 Element <AuthnStatement>
     */
    private fun verifyAuthnStatementAndAttributeStatement() {
        if (node.allChildren("Assertion")
                        .filter { it.children("AuthnStatement").isNotEmpty() }
                        .any { it.children("Subject").isEmpty() })
            throw SAMLComplianceException.create("SAMLCore.2.7.2_a")

        node.allChildren("AuthnStatement").forEach {
            if (it.attributes.getNamedItem("AuthnInstant") == null)
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.2", "AuthnInstant", "AuthnStatement")

            if (it.children("AuthnContext").isEmpty())
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.2", "AuthnContext", "AuthnStatement")
        }
    }

    /**
     * Verify the <AttributeStatement> and <Attribute> elements against the Core Spec
     * 2.7.3 Element <AttributeStatement>
     * 2.7.3.1 Element <Attribute>
     * 2.7.3.2 Element <EncryptedAttribute>
     */
    private fun verifyAttributeElements() {
        // AttributeStatement
        if (node.allChildren("Assertion")
                        .filter { it.children("AttributeStatement").isNotEmpty() }
                        .any { it.children("Subject").isEmpty() })
            throw SAMLComplianceException.create("SAMLCore.2.7.3_a")

        node.allChildren("AttributeStatement").forEach {
            if (it.children("Attribute").isEmpty() && it.children("EncryptedAttribute").isEmpty())
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.3", "Attribute or EncryptedAttribute", "AttributeStatement")
        }

        // Attribute
        node.allChildren("Attribute").forEach {
            if (it.attributes.getNamedItem("Name") == null)
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.3.1", "Name", "Attribute")
            if (it.childNodes.length < 1)
                throw SAMLComplianceException.create("SAMLCore.2.7.3.1_a")


            val nameAttribute = it.attributes.getNamedItem("Name")
            val nameFormatAttribute = it.attributes.getNamedItem("NameFormat")
            val friendlyNameAttribute = it.attributes.getNamedItem("FriendlyName")
            if ((nameAttribute?.textContent?.trim() == ""
                            || nameFormatAttribute?.textContent?.trim() == ""
                            || friendlyNameAttribute?.textContent?.trim() == "")
                    && it.children("AttributeValue").any { StringUtils.isNotBlank(it.textContent) }) {

                if (it.parentNode.localName == "AttributeStatement") throw SAMLComplianceException.create("SAMLCore.2.7.3.1_b", "SAMLCore.2.7.3.1.1_a")
                else throw SAMLComplianceException.create("SAMLCore.2.7.3.1.1_a")
            }

            if ((nameAttribute != null && nameAttribute.textContent == null)
                    || (nameFormatAttribute != null && nameFormatAttribute.textContent == null)
                    || (friendlyNameAttribute != null && friendlyNameAttribute.textContent == null)) {

                it.children("AttributeValue").forEach {
                    val nilAttribute = it.attributes.getNamedItemNS("http://www.w3.org/2001/XMLSchemainstance", "nil")?.textContent
                    if (StringUtils.isNotBlank(it.textContent) || (nilAttribute != "true" && nilAttribute != "1"))
                        throw SAMLComplianceException.create("SAMLCore.2.7.3.1.1_b")
                }
            }
        }

        // EncryptedAttribute
        node.allChildren("EncryptedAttribute").forEach {
            val encryptedData = it.children("EncryptedData")
            if (encryptedData.isEmpty())
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.3.2", "EncryptedData", "EncryptedAttribute")

            if (encryptedData
                            .filter { it.attributes.getNamedItem("Type") != null }
                            .any { it.attributes.getNamedItem("Type").textContent != "http://www.w3.org/2001/04/xmlenc#Element" })
                throw SAMLComplianceException.create("SAMLCore.2.7.3.2_a")
            // todo - The encrypted content MUST contain an element that has a type of or derived from AssertionType.
        }
    }

    /**
     * Verify the <AuthzDecisionStatement> and <Action> elements against the Core Spec
     * 2.7.4 Element <AuthzDecisionStatement>
     * 2.7.4.2 Element <Action>
     */
    private fun verifyAuthzDecisionStatementAndAction() {
        // AuthzDecisionStatement
        node.allChildren("Assertion").forEach {
            if (it.children("AuthzDecisionStatement").isNotEmpty()
                    && it.children("Subject").isEmpty())
                throw SAMLComplianceException.create("SAMLCore.2.7.4_a")
        }

        node.allChildren("AuthzDecisionStatement").forEach {
            if (it.attributes.getNamedItem("Resource") == null)
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.4", "Resource", "AuthzDecisionStatement")
            if (it.attributes.getNamedItem("Decision") == null)
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.4", "Decision", "AuthzDecisionStatement")
            if (it.children("Action").isEmpty())
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.4", "Action", "AuthzDecisionStatement")
        }

        // Action
        val actions = node.allChildren("Action")
        actions.forEach {
            if (it.attributes.getNamedItem("Namespace") == null)
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.4.2", "Namespace", "Action")
        }
    }
}