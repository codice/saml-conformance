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
import org.codice.compliance.SAMLCore_2_7_2
import org.codice.compliance.SAMLCore_2_7_3
import org.codice.compliance.SAMLCore_2_7_4_a
import org.codice.compliance.attributeList
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.verification.core.CommonDataTypeVerifier
import org.codice.compliance.verification.core.CoreVerifier
import org.w3c.dom.Node

internal class StatementVerifier(val node: Node) {
    companion object {
        private const val SUBJECT = "Subject"
        private const val ASSERTION = "Assertion"
    }

    /** 2.7 Statements */
    fun verify() {
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
        node.recursiveChildren("AuthnStatement").forEach {
            CommonDataTypeVerifier.verifyDateTimeValues(it.attributes.getNamedItem("AuthnInstant"))

            it.attributes?.getNamedItem("SessionIndex")?.let {
                CommonDataTypeVerifier.verifyStringValues(it)
            }

            it.attributes?.getNamedItem("SessionNotOnOrAfter")?.let {
                CommonDataTypeVerifier.verifyDateTimeValues(it)
            }
        }

        if (node.recursiveChildren(ASSERTION)
                        .filter { it.children("AuthnStatement").isNotEmpty() }
                        .any { it.children(SUBJECT).isEmpty() })
            throw SAMLComplianceException.create(SAMLCore_2_7_2,
                    message = "An AuthnStatement was found without a Subject element.",
                    node = node)
    }

    /** 2.7.2.1 Element <SubjectLocality> **/
    private fun verifySubjectLocality() {
        node.recursiveChildren("SubjectLocality").forEach {
            it.attributes?.getNamedItem("Address")?.let {
                CommonDataTypeVerifier.verifyStringValues(it)
            }

            it.attributes?.getNamedItem("DNSName")?.let {
                CommonDataTypeVerifier.verifyStringValues(it)
            }
        }
    }

    /** 2.7.2.2 Element <AuthnContext> **/
    private fun verifyAuthnContext() {
        node.recursiveChildren("AuthnContext").forEach {
            it.attributes?.getNamedItem("AuthnContextClassRef")?.let {
                CommonDataTypeVerifier.verifyUriValues(it)
            }
            it.attributes?.getNamedItem("AuthnContextDeclRef")?.let {
                CommonDataTypeVerifier.verifyUriValues(it)
            }
            it.attributes?.getNamedItem("AuthnContextDecl")?.let {
                CommonDataTypeVerifier.verifyUriValues(it)
            }
            it.attributes?.getNamedItem("AuthenticatingAuthority")?.let {
                CommonDataTypeVerifier.verifyUriValues(it)
            }
        }
    }

    /** 2.7.3 Element <AttributeStatement> **/
    private fun verifyAttributeStatement() {
        if (node.recursiveChildren(ASSERTION)
                        .filter { it.children("AttributeStatement").isNotEmpty() }
                        .any { it.children(SUBJECT).isEmpty() })
            throw SAMLComplianceException.create(SAMLCore_2_7_3,
                    message = "An AttributeStatement was found without a Subject element.",
                    node = node)
    }

    /** 2.7.3.1 Element <Attribute> **/
    private fun verifyAttribute() {
        node.recursiveChildren("Attribute").forEach {
            CommonDataTypeVerifier.verifyStringValues(it.attributes.getNamedItem("Name"))

            it.attributes?.getNamedItem("NameFormat")?.let {
                CommonDataTypeVerifier.verifyUriValues(it)
            }

            it.attributes?.getNamedItem("FriendlyName")?.let {
                CommonDataTypeVerifier.verifyStringValues(it)
            }

            CoreVerifier.verifySamlExtensions(it.attributeList(),
                    expectedSamlNames = listOf("Name", "NameFormat", "FriendlyName"))
        }
    }

    /** 2.7.4 Element <AuthzDecisionStatement> **/
    private fun verifyAuthzDecisionStatement() {
        if (node.recursiveChildren(ASSERTION)
                        .any {
                            it.children("AuthzDecisionStatement").isNotEmpty()
                                    && it.children(SUBJECT).isEmpty()
                        })
            throw SAMLComplianceException.create(SAMLCore_2_7_4_a,
                    message = "No Subject element found.",
                    node = node)

        node.recursiveChildren("AuthzDecisionStatement").forEach {
            CommonDataTypeVerifier.verifyUriValues(it.attributes.getNamedItem("Resource"))
        }
    }

    /** 2.7.4.2 Element <Action> **/
    private fun verifyAction() {
        node.recursiveChildren("Action").forEach {
            CommonDataTypeVerifier.verifyUriValues(it.attributes.getNamedItem("Namespace"))
        }
    }
}
