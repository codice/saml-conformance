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
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.w3c.dom.Node

internal class SamlIdentifiersVerifier(val node: Node) {
    companion object {
        private const val RWEDC_NEGATION_URI = "urn:oasis:names:tc:SAML:1.0:action:rwedc-negation"
        private const val RWEDC_URI = "urn:oasis:names:tc:SAML:1.0:action:rwedc"

        private val RWEDC_LIST = listOf(
                "Read",
                "Write",
                "Execute",
                "Delete",
                "Control"
        )
    }

    fun verify() {
        verifyActionNamespaceIdentifiers()
    }

    // 8.1.2 Read/Write/Execute/Delete/Control with Negation
    private fun verifyActionNamespaceIdentifiers() {
        // AuthzDecisionQuery is the only element where "Action" is found (Core 3.3.2.4)
        node.allChildren("AuthzDecisionQuery").forEach({
            val actionList = createActionList(it)

            if (actionList.isNotEmpty()) {
                checkActionList(actionList)
            }
        })
    }

    private fun createActionList(query: Node): List<String> {
        val actionList = mutableListOf<String>()

        query.children("Action").forEach({
            val namespaceValue = it.attributes.getNamedItem("Namespace").nodeValue
            if (namespaceValue == RWEDC_URI || namespaceValue == RWEDC_NEGATION_URI) {
                actionList.add(it.nodeValue)
            }
        })

        return actionList
    }

    private fun checkActionList(actionList: List<String>) {
        RWEDC_LIST.forEach({
            if (actionList.contains(it) && actionList.contains("~$it")) {
                throw SAMLComplianceException.create(
                        codes = SAMLCore_8_1_2,
                        message = """An "AuthzDecisionQuery" element contained an action and """ +
                                """its negated form.""",
                        node = node
                )
            }
        })
    }
}
