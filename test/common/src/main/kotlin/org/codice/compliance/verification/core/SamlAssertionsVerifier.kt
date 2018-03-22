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
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_2_3_a
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_2_3_b
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_2_4_a
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_3_3_a
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_3_3_b
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_3_3_c
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_3_4_a
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_4_1_3
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_5_1_2
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_5_1_5
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_5_1_6_a
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_5_1_6_b
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_5_1_a
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_5_1_b
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_5_1_c
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_7_2
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_7_3
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_7_3_1_1
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_7_3_2_a
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_2_7_4
import org.codice.compliance.SAMLSpecRefMessage.XMLSignature_4_5
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon.Companion.ELEMENT
import org.codice.compliance.utils.TestCommon.Companion.XSI
import org.w3c.dom.Node
import java.time.Instant

@Suppress("LargeClass", "TooManyFunctions"
/* Core assertion verification is a complex, but single responsibility issue. */)
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
                    .createWithPropertyReqMessage("SAMLCore.2.2.4", "EncryptedData", "EncryptedId")

            if (encryptedData
                            .filter { it.attributes.getNamedItem("Type") != null }
                            .any { it.attributes.getNamedItem("Type").textContent != ELEMENT })
                throw SAMLComplianceException.create(SAMLCore_2_2_4_a,
                        message = "Type attribute found with an incorrect value.")
            // todo - For The encrypted content MUST contain an element that has a type of NameIDType or AssertionType,
            // or a type that is derived from BaseIDAbstractType, NameIDType, or AssertionType.
        }
        // todo - Encrypted identifiers are intended as a privacy protection mechanism when the plain-text value passes
        // through an intermediary. As such, the ciphertext MUST be unique to any given encryption operation. For more
        // on such issues, see [XMLEnc] Section 6.3.
    }

    /**
     * Verify the <Assertion> Element against the Core Spec document
     * 2.3.3 Element <Assertion>
     */
    @Suppress("ComplexCondition")
    private fun verifyCoreAssertion() {
        node.allChildren("Assertion").forEach {
            if (it.attributes.getNamedItem("Version")?.textContent == null)
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.2.3.3", "Version", "Assertion")
            if (it.attributes.getNamedItem("Version").textContent != "2.0")
                throw SAMLComplianceException.createWithPropertyNotEqualMessage(SAMLCore_2_3_3_a,
                        "Version",
                        it.attributes.getNamedItem("Version").textContent,
                        "2.0")

            if (it.attributes.getNamedItem("ID") == null)
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.2.3.3", "ID", "Assertion")
            verifyIdValues(it.attributes.getNamedItem("ID"), SAMLCore_2_3_3_b)

            if (it.attributes.getNamedItem("IssueInstant") == null)
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.2.3.3",
                        "IssueInstant",
                        "Assertion")
            verifyTimeValues(it.attributes.getNamedItem("IssueInstant"), SAMLCore_2_3_3_c)

            if (it.children("Issuer").isEmpty())
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.2.3.3", "Issuer", "Assertion")

            val statements = it.children("Statement")
            if (statements.any { it.attributes.getNamedItemNS(XSI, "type") == null })
                throw SAMLComplianceException.create(SAMLCore_2_2_3_a,
                        message = "Statement element found without a type.")

            if (statements.isEmpty()
                    && it.children("AuthnStatement").isEmpty()
                    && it.children("AuthzDecisionStatement").isEmpty()
                    && it.children("AttributeStatement").isEmpty()
                    && it.children("Subject").isEmpty())
                throw SAMLComplianceException.create(SAMLCore_2_2_3_b,
                        message = "No Subject or Statement elements found.")
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
                        .createWithPropertyReqMessage("SAMLCore.2.3.4", "EncryptedData", "EncryptedAssertion")

            if (encryptedData
                            .filter { it.attributes.getNamedItem("Type") != null }
                            .any { it.attributes.getNamedItem("Type").textContent != ELEMENT })
                throw SAMLComplianceException.create(SAMLCore_2_3_4_a,
                        message = "Type attribute found with an incorrect value.")
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
                    .createWithPropertyReqMessage("SAMLCore.2.4.1.1", "Method", "SubjectConfirmation")

        // SubjectConfirmationData
        node.allChildren("SubjectConfirmationData").forEach {
            // todo - SAML extensions MUST NOT add local (non-namespace-qualified) XML attributes or XML attributes
            // qualified by a SAML-defined namespace to the SubjectConfirmationDataType complex type or a derivation
            // of it; such attributes are reserved for future maintenance and enhancement of SAML itself.

            val notBefore = it.attributes.getNamedItem("NotBefore")
            val notOnOrAfter = it.attributes.getNamedItem("NotOnOrAfter")
            if (notBefore != null
                    && notOnOrAfter != null) {
                val notBeforeValue = Instant.parse(notBefore.textContent)
                val notOnOrAfterValue = Instant.parse(notOnOrAfter.textContent)
                if (notBeforeValue.isAfter(notOnOrAfterValue)) throw SAMLComplianceException.create(SAMLCore_2_5_1_2,
                        message = "NotBefore element with value $notBeforeValue is not less than NotOnOrAfter " +
                                "element with value $notOnOrAfterValue.")
            }

            // KeyInfoConfirmationDataType
            if (it.attributes
                            ?.getNamedItemNS(XSI, "type")
                            ?.textContent?.contains("KeyInfoConfirmationDataType") == true
                    && it.children("KeyInfo").any { it.children("KeyValue").size > 1 })
                throw SAMLComplianceException.create(SAMLCore_2_4_1_3, XMLSignature_4_5,
                        message = "Multiple Keys found within the KeyInfo element.")
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
            val conditionsElement = it

            verifyConditionType(conditionsElement)

            verifyOneTimeUse(conditionsElement)

            verifyProxyRestrictions(conditionsElement)

            val notBefore = it.attributes.getNamedItem("NotBefore")
            val notOnOrAfter = it.attributes.getNamedItem("NotOnOrAfter")
            if (notBefore != null
                    && notOnOrAfter != null) {
                val notBeforeValue = Instant.parse(notBefore.textContent)
                val notOnOrAfterValue = Instant.parse(notOnOrAfter.textContent)
                if (notBeforeValue.isAfter(notOnOrAfterValue)) throw SAMLComplianceException.create(SAMLCore_2_5_1_2,
                        message = "NotBefore element with value $notBeforeValue is not less than NotOnOrAfter " +
                                "element with value $notOnOrAfterValue.")
            }
        }
    }

    private fun verifyProxyRestrictions(conditionsElement: Node) {
        val proxyRestrictions = conditionsElement.children("ProxyRestriction")
        if (!proxyRestrictions.isNotEmpty()) return

        if (proxyRestrictions.size > 1)
            throw SAMLComplianceException.create(SAMLCore_2_5_1_c, SAMLCore_2_5_1_6_b,
                    message = "Cannot have more than one ProxyRestriction element.")

        val proxyRestrictionAudiences = proxyRestrictions
                .flatMap { it.children("Audience") }
                .map { it.textContent }
                .toList()

        if (!proxyRestrictionAudiences.isNotEmpty()) return

        val audienceRestrictions = conditionsElement.allChildren("AudienceRestriction")

        if (audienceRestrictions.isEmpty()) throw SAMLComplianceException.create(SAMLCore_2_5_1_6_a,
                message = "There must be an AudienceRestriction element.")

        audienceRestrictions.forEach {
            val audienceRestrictionAudiences = it.children("Audience")
            if (audienceRestrictionAudiences.isEmpty())
                throw SAMLComplianceException.create(SAMLCore_2_5_1_6_a,
                        message = "The AudienceRestriction element must contain at least one Audience " +
                                "element.")
            it.children("Audience").forEach {
                if (!proxyRestrictionAudiences.contains(it.textContent))
                    throw SAMLComplianceException.create(SAMLCore_2_5_1_6_a,
                            message = "The AudienceRestriction can only have Audience elements that are " +
                                    "also in the ProxyRestriction element.")
            }
        }
    }

    private fun verifyOneTimeUse(conditionsElement: Node) {
        if (conditionsElement.children("OneTimeUse").size > 1)
            throw SAMLComplianceException.create(SAMLCore_2_5_1_b, SAMLCore_2_5_1_5,
                    message = "Cannot have more than one OneTimeUse element.")
    }

    private fun verifyConditionType(conditionsElement: Node) {
        if (conditionsElement.children("Condition")
                        .any { it.attributes.getNamedItemNS(XSI, "type") == null })
            throw SAMLComplianceException.create(SAMLCore_2_5_1_a, message = "Condition found without a type.")
    }

    /**
     * Verify the <AuthnStatement> element against the Core Spec
     * 2.7.2 Element <AuthnStatement>
     */
    private fun verifyAuthnStatementAndAttributeStatement() {
        if (node.allChildren("Assertion")
                        .filter { it.children("AuthnStatement").isNotEmpty() }
                        .any { it.children("Subject").isEmpty() })
            throw SAMLComplianceException.create(SAMLCore_2_7_2,
                    message = "An AuthnStatement was found without a Subject element.")

        node.allChildren("AuthnStatement").forEach {
            if (it.attributes.getNamedItem("AuthnInstant") == null)
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.2.7.2",
                        "AuthnInstant",
                        "AuthnStatement")

            if (it.children("AuthnContext").isEmpty())
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.2.7.2",
                        "AuthnContext",
                        "AuthnStatement")
        }
    }

    /**
     * Verify the <AttributeStatement> and <Attribute> elements against the Core Spec
     * 2.7.3 Element <AttributeStatement>
     * 2.7.3.1 Element <Attribute>
     * 2.7.3.2 Element <EncryptedAttribute>
     */
    private fun verifyAttributeElements() {
        verifyAttributeStatement()
        verifyAttribute()
        verifyEncryptedAttribute()
    }

    private fun verifyEncryptedAttribute() {
        node.allChildren("EncryptedAttribute").forEach {
            val encryptedData = it.children("EncryptedData")
            if (encryptedData.isEmpty())
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.2.7.3.2",
                        "EncryptedData",
                        "EncryptedAttribute")

            if (encryptedData
                            .filter { it.attributes.getNamedItem("Type") != null }
                            .any { it.attributes.getNamedItem("Type").textContent != ELEMENT })
                throw SAMLComplianceException.createWithPropertyNotEqualMessage(SAMLCore_2_7_3_2_a,
                        "Type",
                        it.attributes.getNamedItem("Type").textContent,
                        ELEMENT)
            // todo - The encrypted content MUST contain an element that has a type of or derived from AssertionType.
        }
    }

    @Suppress("ComplexCondition")
    private fun verifyAttribute() {
        node.allChildren("Attribute").forEach {
            if (it.attributes.getNamedItem("Name") == null)
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.2.7.3.1", "Name", "Attribute")

            val nameAttribute = it.attributes.getNamedItem("Name")
            val nameFormatAttribute = it.attributes.getNamedItem("NameFormat")
            val friendlyNameAttribute = it.attributes.getNamedItem("FriendlyName")

            if ((nameAttribute != null && nameAttribute.textContent == null)
                    || (nameFormatAttribute != null && nameFormatAttribute.textContent == null)
                    || (friendlyNameAttribute != null && friendlyNameAttribute.textContent == null)) {
                verifyAttributeValue(it)
            }
        }
    }

    private fun verifyAttributeValue(it: Node) {
        it.children("AttributeValue").forEach {
            val nilAttribute = it.attributes.getNamedItemNS(XSI, "nil")?.textContent
            if (StringUtils.isNotBlank(it.textContent) || (nilAttribute != "true" && nilAttribute != "1"))
                throw SAMLComplianceException.createWithPropertyInvalidMessage(SAMLCore_2_7_3_1_1,
                        "xsi:nil XML attribute",
                        nilAttribute)
        }
    }

    private fun verifyAttributeStatement() {
        if (node.allChildren("Assertion")
                        .filter { it.children("AttributeStatement").isNotEmpty() }
                        .any { it.children("Subject").isEmpty() })
            throw SAMLComplianceException.create(SAMLCore_2_7_3,
                    message = "An AttributeStatement was found without a Subject element.")

        node.allChildren("AttributeStatement").forEach {
            if (it.children("Attribute").isEmpty() && it.children("EncryptedAttribute").isEmpty())
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.2.7.3",
                        "Attribute or EncryptedAttribute",
                        "AttributeStatement")
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
                throw SAMLComplianceException.create(SAMLCore_2_7_4, message = "No Subject element found.")
        }

        node.allChildren("AuthzDecisionStatement").forEach {
            if (it.attributes.getNamedItem("Resource") == null)
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.2.7.4",
                        "Resource",
                        "AuthzDecisionStatement")
            if (it.attributes.getNamedItem("Decision") == null)
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.2.7.4",
                        "Decision",
                        "AuthzDecisionStatement")
            if (it.children("Action").isEmpty())
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.2.7.4",
                        "Action",
                        "AuthzDecisionStatement")
        }

        // Action
        val actions = node.allChildren("Action")
        actions.forEach {
            if (it.attributes.getNamedItem("Namespace") == null)
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.2.7.4.2", "Namespace", "Action")
        }
    }
}
