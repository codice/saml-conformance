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
import org.w3c.dom.Node

internal class SamlIdentifiersVerifier(val node: Node) {
    companion object {
        val actionNamespaces = listOf(
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
        node.allChildren("Action").forEach({ action ->
            action.nodeValue?.let {
                checkActionNamespaceValue(it)
            }
        })
    }

    private fun checkActionNamespaceValue(nodeValue: String) {
        actionNamespaces.forEach({
            if (nodeValue.contains(it) && nodeValue.contains("~$it")) {
                throw SAMLComplianceException.create(
                        codes = *arrayOf(SAMLCore_8_1_2),
                        message = "An action contained both $it and ~$it",
                        node = node
                )
            }
        })
    }
}
