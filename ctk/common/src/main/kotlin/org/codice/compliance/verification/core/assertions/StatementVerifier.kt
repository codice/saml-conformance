/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.core.assertions

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_2_7_2_a
import org.codice.compliance.SAMLCore_2_7_3_a
import org.codice.compliance.SAMLCore_2_7_4_a
import org.codice.compliance.attributeNode
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.report.Report
import org.codice.compliance.Section.CORE_2_7
import org.codice.compliance.utils.ASSERTION
import org.codice.compliance.utils.AUTHN_STATEMENT
import org.codice.compliance.utils.SESSION_INDEX
import org.codice.compliance.utils.SUBJECT
import org.codice.compliance.verification.core.CommonDataTypeVerifier
import org.w3c.dom.Node

internal class StatementVerifier(val node: Node) {

    /** 2.7 Statements */
    fun verify() {
        CORE_2_7.start()
        verifyAuthnStatement()
        verifySubjectLocality()
        verifyAuthnContext()
        verifyAttributeStatement()
        verifyAttribute()
        verifyAuthzDecisionStatement()
        verifyAction()
    }

    /** 2.7.2 Element <AuthnStatement> **/
    private fun verifyAuthnStatement() {
        node.recursiveChildren(AUTHN_STATEMENT).forEach {
            CommonDataTypeVerifier.verifyDateTimeValue(it.attributeNode("AuthnInstant"))

            it.attributeNode(SESSION_INDEX)?.let {
                CommonDataTypeVerifier.verifyStringValue(it)
            }

            it.attributeNode("SessionNotOnOrAfter")?.let {
                CommonDataTypeVerifier.verifyDateTimeValue(it)
            }
        }

        if (node.recursiveChildren(ASSERTION)
                        .filter { it.children(AUTHN_STATEMENT).isNotEmpty() }
                        .any { it.children(SUBJECT).isEmpty() }) {
            Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_2_7_2_a,
                    message = "An AuthnStatement was found without a Subject element.",
                    node = node))
        }
    }

    /** 2.7.2.1 Element <SubjectLocality> **/
    private fun verifySubjectLocality() {
        node.recursiveChildren("SubjectLocality").forEach {
            it.attributeNode("Address")?.let {
                CommonDataTypeVerifier.verifyStringValue(it)
            }

            it.attributeNode("DNSName")?.let {
                CommonDataTypeVerifier.verifyStringValue(it)
            }
        }
    }

    /** 2.7.2.2 Element <AuthnContext> **/
    private fun verifyAuthnContext() {
        node.recursiveChildren("AuthnContext").forEach {
            it.attributeNode("AuthnContextClassRef")?.let {
                CommonDataTypeVerifier.verifyUriValue(it)
            }
            it.attributeNode("AuthnContextDeclRef")?.let {
                CommonDataTypeVerifier.verifyUriValue(it)
            }
            it.attributeNode("AuthnContextDecl")?.let {
                CommonDataTypeVerifier.verifyUriValue(it)
            }
            it.attributeNode("AuthenticatingAuthority")?.let {
                CommonDataTypeVerifier.verifyUriValue(it)
            }
        }
    }

    /** 2.7.3 Element <AttributeStatement> **/
    private fun verifyAttributeStatement() {
        if (node.recursiveChildren(ASSERTION)
                        .filter { it.children("AttributeStatement").isNotEmpty() }
                        .any { it.children(SUBJECT).isEmpty() }) {
            Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_2_7_3_a,
                    message = "An AttributeStatement was found without a Subject element.",
                    node = node))
        }
    }

    /** 2.7.3.1 Element <Attribute> **/
    private fun verifyAttribute() {
        node.recursiveChildren("Attribute").forEach {
            CommonDataTypeVerifier.verifyStringValue(it.attributes.getNamedItem("Name"))

            it.attributeNode("NameFormat")?.let {
                CommonDataTypeVerifier.verifyUriValue(it)
            }

            it.attributeNode("FriendlyName")?.let {
                CommonDataTypeVerifier.verifyStringValue(it)
            }
        }
    }

    /** 2.7.4 Element <AuthzDecisionStatement> **/
    private fun verifyAuthzDecisionStatement() {
        if (node.recursiveChildren(ASSERTION)
                        .any {
                            it.children("AuthzDecisionStatement").isNotEmpty() &&
                                    it.children(SUBJECT).isEmpty()
                        }) {
            Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_2_7_4_a,
                    message = "No Subject element found.",
                    node = node))
        }

        node.recursiveChildren("AuthzDecisionStatement").forEach {
            CommonDataTypeVerifier.verifyUriValue(it.attributeNode("Resource"))
        }
    }

    /** 2.7.4.2 Element <Action> **/
    private fun verifyAction() {
        node.recursiveChildren("Action").forEach {
            CommonDataTypeVerifier.verifyUriValue(it.attributeNode("Namespace"))
        }
    }
}
