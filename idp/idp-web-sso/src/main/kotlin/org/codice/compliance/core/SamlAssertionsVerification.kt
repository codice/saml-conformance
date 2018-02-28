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
package org.codice.compliance.core

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.w3c.dom.Node
import java.time.Instant

/**
 * Verify assertions against the Core Spec document
 * 2 SAML Assertions
 */
fun verifyAssertions(response: Node) {
    verifyEncryptedId(response)
    verifyCoreAssertion(response)
    verifyEncryptedAssertion(response)
    verifySubjectElements(response)
    verifyConditions(response)
    verifyAuthnStatementAndAttributeStatement(response)
    verifyAttributeElements(response)
    verifyAuthzDecisionStatementAndAction(response)
}

/**
 * Verify the <EncryptedId> Element against the Core Spec document
 * 2.2.4 Element <EncryptedID>
 */
fun verifyEncryptedId(response: Node) {
    val encryptedIds = response.allChildren("EncryptedID")
    encryptedIds.forEach {
        val encryptedData = it.children("EncryptedData")
        if (encryptedData.isEmpty()) throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.2.4", "EncryptedData", "EncryptedId")

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
fun verifyCoreAssertion(response: Node) {
    val assertions = response.allChildren("Assertion")
    assertions.forEach {
        if (it.attributes.getNamedItem("Version")?.textContent == null)
            throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.3.3", "Version", "Assertion")
        if (it.attributes.getNamedItem("Version").textContent != "2.0")
            throw SAMLComplianceException.create("SAMLCore.2.3.3_a")

        if (it.attributes.getNamedItem("ID") == null)
            throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.3.3", "ID", "Assertion")
        verifyIdValues(it.attributes.getNamedItem("ID"), "SAMLCore.2.3.3_b")

        if (it.attributes.getNamedItem("IssueInstant") == null)
            throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.3.3", "IssueInstant", "Assertion")
        verifyIdValues(it.attributes.getNamedItem("IssueInstant"), "SAMLCore.2.3.3_c")

        val issuers = it.children("Issuer")
        if (issuers.isEmpty()) throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.3.3", "Issuer", "Assertion")

        val statements = it.children("Statement")
        if (statements.isNotEmpty() && statements.any { it.attributes.getNamedItem("xsi:type") == null })
            throw SAMLComplianceException.create("SAMLCore.2.2.3_a")

        val subjects = it.children("Subject")
        val authnStatements = it.children("AuthnStatement")
        val authzDecisionStatements = it.children("AuthzDecisionStatement")
        val attributeStatements = it.children("AttributeStatement")
        if (statements.isEmpty()
                && authnStatements.isEmpty()
                && authzDecisionStatements.isEmpty()
                && attributeStatements.isEmpty()
                && subjects.isEmpty())
            throw SAMLComplianceException.create("SAMLCore.2.2.3_b")

    }
}

/**
 * Verify the <Assertion> element against the Core Spec document
 * 2.3.4 Element <EncryptedAssertion>
 */
fun verifyEncryptedAssertion(response: Node) {
    val encryptedAssertion = response.allChildren("EncryptedAssertion")
    if (encryptedAssertion.isNotEmpty()) {
        encryptedAssertion.forEach {
            val encryptedData = it.children("EncryptedData")
            if (encryptedData.isEmpty()) throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.3.4", "EncryptedData", "EncryptedAssertion")

            if (encryptedData
                    .filter { it.attributes.getNamedItem("Type") != null }
                    .all { it.attributes.getNamedItem("Type").textContent == "http://www.w3.org/2001/04/xmlenc#Element" })
                throw SAMLComplianceException.create("SAMLCore.2.3.4")
            // todo - The encrypted content MUST contain an element that has a type of or derived from AssertionType.
        }
    }
}

/**
 * Verify subject elements against the Core Spec
 * 2.4.1.1 Element <SubjectConfirmation>
 * 2.4.1.2 Element <SubjectConfirmationData>
 */
fun verifySubjectElements(response: Node) {
    // SubjectConfirmation
    val subjectConfirmations = response.allChildren("SubjectConfirmation")
    if (subjectConfirmations.any { it.attributes.getNamedItem("Method") == null })
        throw SAMLComplianceException.createWithReqMessage("2.4.1.1", "Method", "SubjectConfirmation")

    // SubjectConfirmationData
    val subjectConfirmationData = response.allChildren("SubjectConfirmationData")
    // todo - SAML extensions MUST NOT add local (non-namespace-qualified) XML attributes or XML attributes qualified by a SAML-defined
    // namespace to the SubjectConfirmationDataType complex type or a derivation of it; such attributes are reserved for future maintenance
    // and enhancement of SAML itself.
}


/**
 * Verify the <Conditions> element against the Core Spec
 * 2.5.1 Element <Conditions>
 */
fun verifyConditions(response: Node) {
    val conditions = response.allChildren("Conditions")
    conditions.forEach {
        val conditionList = it.children("Condition")
        if (conditionList.isNotEmpty() && conditionList.any { it.attributes.getNamedItem("xsi:type") == null })
            throw SAMLComplianceException.create("SAMLCore.2.5.1_a")

        if (it.children("OneTimeUse").size > 1)
            throw SAMLComplianceException.create("SAMLCore.2.5.1_b", "SAMLCore.2.5.1.5_a")

        if (it.children("ProxyRestriction").size > 1)
            throw SAMLComplianceException.create("SAMLCore.2.5.1_c, SAMLCore.2.5.1.6_a")

        val notBefore = it.attributes.getNamedItem("NotBefore")
        val notOnOrAfter = it.attributes.getNamedItem("NotOnOrAfter")
        if (notBefore != null
                && notOnOrAfter != null
                && Instant.parse(notBefore.textContent) > Instant.parse(notOnOrAfter.textContent))
            throw SAMLComplianceException.create("SAMLCore.2.5.1.2")
    }
}

/**
 * Verify the <AuthnStatement> element against the Core Spec
 * 2.7.2 Element <AuthnStatement>
 */
fun verifyAuthnStatementAndAttributeStatement(response: Node) {
    val assertions = response.allChildren("Assertion")
    if (assertions
            .filter { it.children("AuthnStatement").isNotEmpty() }
            .any { it.children("Subject").isEmpty() })
        throw SAMLComplianceException.create("SAMLCore.2.7.2_a")

    val authnStatements = response.allChildren("AuthnStatement")
    authnStatements.forEach {
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
fun verifyAttributeElements(response: Node) {
    // AttributeStatement
    val assertions = response.allChildren("Assertion")
    if (assertions
            .filter { it.children("AttributeStatement").isNotEmpty() }
            .any { it.children("Subject").isEmpty() })
        throw SAMLComplianceException.create("SAMLCore.2.7.3_a")

    // Attribute
    val attributes = response.allChildren("Attribute")
    attributes.forEach {
        if (it.attributes.getNamedItem("Name") == null)
            throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.3.1", "Name", "Attribute")
        if (it.childNodes.length < 1)
            throw SAMLComplianceException.create("SAMLCore.2.7.3.1_a")
    }

    // EncryptedAttribute
    val encryptedAttribute = response.allChildren("EncryptedAttribute")
    if (encryptedAttribute.isNotEmpty()) {
        encryptedAttribute.forEach {
            val encryptedData = it.children("EncryptedData")
            if (encryptedData.isEmpty()) throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.3.2", "EncryptedData", "EncryptedAttribute")

            if (encryptedData
                    .filter { it.attributes.getNamedItem("Type") != null }
                    .all { it.attributes.getNamedItem("Type").textContent == "http://www.w3.org/2001/04/xmlenc#Element" })
                throw SAMLComplianceException.create("SAMLCore.2.7.3.2_a")
            // todo - The encrypted content MUST contain an element that has a type of or derived from AssertionType.
        }
    }
}

/**
 * Verify the <AuthzDecisionStatement> and <Action> elements against the Core Spec
 * 2.7.4 Element <AuthzDecisionStatement>
 * 2.7.4.2 Element <Action>
 */
fun verifyAuthzDecisionStatementAndAction(response: Node) {
    // AuthzDecisionStatement
    val assertions = response.allChildren("Assertion")
    assertions.forEach {
        if (it.children("AuthzDecisionStatement").isNotEmpty()
                && it.children("Subject").isEmpty())
            throw SAMLComplianceException.create("SAMLCore.2.7.4_a")
    }

    val authzDecisionStatements = response.allChildren("AuthzDecisionStatement")
    authzDecisionStatements.forEach {
        if (it.attributes.getNamedItem("Resource") == null) throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.4", "Resource", "AuthzDecisionStatement")
        if (it.attributes.getNamedItem("Decision") == null) throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.4", "Decision", "AuthzDecisionStatement")
        if (it.children("Action").isEmpty()) throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.4", "Action", "AuthzDecisionStatement")
    }

    // Action
    val actions = response.allChildren("Action")
    actions.forEach {
        if (it.attributes.getNamedItem("Namespace") == null) throw SAMLComplianceException.createWithReqMessage("SAMLCore.2.7.4.2", "Namespace", "Action")
    }
}