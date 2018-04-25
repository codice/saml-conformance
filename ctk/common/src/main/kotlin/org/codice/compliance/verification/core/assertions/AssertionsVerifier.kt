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
package org.codice.compliance.verification.core.assertions

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_2_2_3_a
import org.codice.compliance.SAMLCore_2_2_3_b
import org.codice.compliance.SAMLCore_2_3_3_a
import org.codice.compliance.SAMLCore_2_3_3_b
import org.codice.compliance.SAMLCore_2_3_3_c
import org.codice.compliance.attributeNode
import org.codice.compliance.attributeNodeNS
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon.Companion.ASSERTION
import org.codice.compliance.utils.TestCommon.Companion.AUTHN_STATEMENT
import org.codice.compliance.utils.TestCommon.Companion.ID
import org.codice.compliance.utils.TestCommon.Companion.SAML_VERSION
import org.codice.compliance.utils.TestCommon.Companion.SUBJECT
import org.codice.compliance.utils.TestCommon.Companion.VERSION
import org.codice.compliance.utils.TestCommon.Companion.XSI
import org.codice.compliance.verification.core.CommonDataTypeVerifier
import org.w3c.dom.Node

internal class AssertionsVerifier(val node: Node) {
    /** 2.3 Assertions */
    fun verify() {
        verifyAssertionURIRef()
        verifyAssertion()
    }

    /** 2.3.2 Element <AssertionURIRef> */
    private fun verifyAssertionURIRef() {
        node.recursiveChildren("AssertionURIRef").forEach {
            CommonDataTypeVerifier.verifyUriValues(it)
        }
    }

    /** 2.3.3 Element <Assertion> */
    @Suppress("ComplexCondition")
    private fun verifyAssertion() {
        node.recursiveChildren(ASSERTION).forEach {
            val version = it.attributeNode(VERSION)
            if (version?.textContent != SAML_VERSION)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_2_3_3_a,
                        property = VERSION,
                        actual = version?.textContent,
                        expected = SAML_VERSION,
                        node = node)

            CommonDataTypeVerifier.verifyStringValues(version)
            CommonDataTypeVerifier.verifyIdValues(it.attributeNode(ID),
                    SAMLCore_2_3_3_b)
            CommonDataTypeVerifier.verifyDateTimeValues(it.attributeNode("IssueInstant"),
                    SAMLCore_2_3_3_c)

            val statements = it.children("Statement")
            if (statements.any { it.attributeNodeNS(XSI, "type") == null })
                throw SAMLComplianceException.create(SAMLCore_2_2_3_a,
                        message = "Statement element found without a type.",
                        node = node)

            if (statements.isEmpty()
                    && it.children(AUTHN_STATEMENT).isEmpty()
                    && it.children("AuthzDecisionStatement").isEmpty()
                    && it.children("AttributeStatement").isEmpty()
                    && it.children(SUBJECT).isEmpty())
                throw SAMLComplianceException.create(SAMLCore_2_2_3_b,
                        message = "No Subject or Statement elements found.",
                        node = node)
        }
    }
}
