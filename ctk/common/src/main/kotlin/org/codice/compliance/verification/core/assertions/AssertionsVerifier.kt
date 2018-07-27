/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.core.assertions

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_2_2_3_a
import org.codice.compliance.SAMLCore_2_2_3_b
import org.codice.compliance.SAMLCore_2_3_3_b
import org.codice.compliance.SAMLCore_2_3_3_c
import org.codice.compliance.attributeNode
import org.codice.compliance.attributeNodeNS
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.ASSERTION
import org.codice.compliance.utils.AUTHN_STATEMENT
import org.codice.compliance.utils.ID
import org.codice.compliance.utils.SUBJECT
import org.codice.compliance.utils.VERSION
import org.codice.compliance.utils.XSI
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
            CommonDataTypeVerifier.verifyUriValue(it)
        }
    }

    /** 2.3.3 Element <Assertion> */
    @Suppress("ComplexCondition")
    private fun verifyAssertion() {
        node.recursiveChildren(ASSERTION).forEach {
            CommonDataTypeVerifier.verifyStringValue(it.attributeNode(VERSION))
            CommonDataTypeVerifier.verifyIdValue(it.attributeNode(ID),
                    SAMLCore_2_3_3_b)
            CommonDataTypeVerifier.verifyDateTimeValue(it.attributeNode("IssueInstant"),
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
