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
import org.codice.compliance.recursiveChildren
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.SAML_VERSION
import org.codice.compliance.verification.core.CommonDataTypeVerifier
import org.w3c.dom.Node

internal class AssertionsVerifier(val node: Node) {
    companion object {
        private const val VERSION = "Version"
    }

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
        node.recursiveChildren("Assertion").forEach {
            val version = it.attributes.getNamedItem(VERSION)
            if (version.textContent != SAML_VERSION)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_2_3_3_a,
                        property = VERSION,
                        actual = it.attributes.getNamedItem(VERSION).textContent,
                        expected = SAML_VERSION,
                        node = node)

            CommonDataTypeVerifier.verifyStringValues(version)
            CommonDataTypeVerifier.verifyIdValues(it.attributes.getNamedItem("ID"),
                    SAMLCore_2_3_3_b)
            CommonDataTypeVerifier.verifyDateTimeValues(it.attributes.getNamedItem("IssueInstant"),
                    SAMLCore_2_3_3_c)

            val statements = it.children("Statement")
            if (statements.any { it.attributes?.getNamedItemNS(TestCommon.XSI, "type") == null })
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
}
