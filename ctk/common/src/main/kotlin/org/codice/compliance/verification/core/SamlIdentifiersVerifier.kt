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
import org.codice.compliance.SAMLCore_8_1_2
import org.codice.compliance.SAMLCore_8_2_2
import org.codice.compliance.SAMLCore_8_2_3
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.w3c.dom.DOMException
import org.w3c.dom.Node
import java.net.URI
import java.net.URISyntaxException
import javax.xml.parsers.DocumentBuilderFactory

internal class SamlIdentifiersVerifier(val node: Node) {
    companion object {
        private const val ATTRIBUTE_NAME_FORMAT_URI =
                "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
        private const val ATTRIBUTE_NAME_FORMAT_BASIC =
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"

        private val RWEDC_URI_SET = setOf(
                "urn:oasis:names:tc:SAML:1.0:action:rwedc-negation",
                "urn:oasis:names:tc:SAML:1.0:action:rwedc"
        )
    }

    fun verify() {
        verifyActionNamespaceIdentifiers()
        verifyAttributeNameFormatIdentifiers()
    }

    // 8.1.2 Read/Write/Execute/Delete/Control with Negation
    private fun verifyActionNamespaceIdentifiers() {
        // AuthzDecisionQuery is the only element where "Action" is found (Core 3.3.2.4)
        node.recursiveChildren("AuthzDecisionQuery").forEach({
            val actionList = createActionList(it)

            if (actionList.isNotEmpty()) {
                checkActionList(actionList)
            }
        })
    }

    private fun createActionList(query: Node): List<String> {
        return query.children("Action")
                .filter { it.attributes.getNamedItem("Namespace").nodeValue in RWEDC_URI_SET }
                .map { it.nodeValue }
                .toList()
    }

    private fun checkActionList(actionList: List<String>) {
        val (negated, notNegated) = actionList.partition { it.startsWith("~") }
        notNegated.forEach {
            if ("~$it" in negated) {
                throw SAMLComplianceException.create(
                        SAMLCore_8_1_2,
                        message = "An \"AuthzDecisionQuery\" element contained an action and its " +
                                "negated form.",
                        node = node
                )
            }
        }
    }

    // 8.2 URI/Basic name attribute formats
    private fun verifyAttributeNameFormatIdentifiers() {
        node.recursiveChildren("Attribute").forEach {
            val name = it.attributes.getNamedItem("Name")
            val nameFormat = it.attributes?.getNamedItem("NameFormat")
            if (name == null || nameFormat?.textContent == null) {
                return
            }

            when (nameFormat.textContent) {
                ATTRIBUTE_NAME_FORMAT_URI -> {
                    try {
                        URI(name.textContent)
                    } catch (e: URISyntaxException) {
                        throw SAMLComplianceException.create(
                                SAMLCore_8_2_2,
                                message = "Attribute name does not match its declared format",
                                node = node
                        )
                    }
                }
                ATTRIBUTE_NAME_FORMAT_BASIC -> {
                    try {
                        DocumentBuilderFactory.newInstance()
                                .newDocumentBuilder()
                                .newDocument()
                                .createElement(name.textContent)
                    } catch (e: DOMException) {
                        throw SAMLComplianceException.create(
                                SAMLCore_8_2_3,
                                message = "Attribute name does not match its declared format",
                                node = node
                        )
                    }
                }
            }
        }
    }
}
