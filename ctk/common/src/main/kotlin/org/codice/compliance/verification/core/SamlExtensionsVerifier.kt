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

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_SamlExtensions
import org.codice.compliance.attributeList
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon
import org.w3c.dom.Attr
import org.w3c.dom.Element
import org.w3c.dom.Node

class SamlExtensionsVerifier(val node: Node) {

    /**
     * Verify SAML extension attributes or elements against the Core Spec document
     *
     * 2.4.1.2 Element <SubjectConfirmationData>
     * 2.7.3.1 Element <Attribute>
     * 3.2.2 Complex Type StatusResponseType
     */
    internal fun verify() {
        if (node.localName == "Response") {
            verifySamlExtensions(node.children(),
                    expectedSamlNames = listOf("Issuer", "Signature", "Status", "Assertion",
                            "EncryptedAssertion"))
        }

        node.recursiveChildren("Attribute").forEach {
            verifySamlExtensions(it.attributeList(),
                    expectedSamlNames = listOf("Name", "NameFormat", "FriendlyName"))
        }

        node.recursiveChildren("SubjectConfirmationData").forEach {
            verifySamlExtensions(it.attributeList(),
                    expectedSamlNames = listOf("NotBefore", "NotOnOrAfter", "Recipient",
                            "InResponseTo", "Address"))
        }
    }

    internal fun verifySamlExtensions(nodes: List<Node>,
                                      expectedSamlNames: List<String>) {
        nodes.forEach {
            if (isNullNamespace(it) || (isSamlNamespace(it)
                            && !expectedSamlNames.contains(it.localName))) {
                throw SAMLComplianceException.create(SAMLCore_SamlExtensions,
                        message = "An invalid SAML extension was found.",
                        node = it)
            }
        }
    }

    private fun isNullNamespace(node: Node): Boolean {
        return with(node) {
            when (this) {
                is Attr -> namespaceURI == null && ownerElement.namespaceURI == null
                is Element -> namespaceURI == null
                else -> throw UnknownError("Unknown Node type found")
            }
        }
    }

    private fun isSamlNamespace(node: Node): Boolean {
        return with(node) {
            when (this) {
                is Attr -> {
                    namespaceURI == TestCommon.SAML_NAMESPACE
                            || ownerElement.namespaceURI == TestCommon.SAML_NAMESPACE
                }
                is Element -> namespaceURI == TestCommon.SAML_NAMESPACE
                else -> throw UnknownError("Unknown Node type found")
            }
        }
    }
}
