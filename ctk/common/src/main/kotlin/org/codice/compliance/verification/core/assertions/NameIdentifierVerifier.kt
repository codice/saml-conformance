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

import org.codice.compliance.attributeNode
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.FORMAT
import org.codice.compliance.utils.SP_NAME_QUALIFIER
import org.codice.compliance.verification.core.CommonDataTypeVerifier
import org.w3c.dom.Node

internal class NameIdentifierVerifier(val node: Node) {
    companion object {

        /** 2.2.1 Element <BaseID> */
        private fun verifyIdNameQualifiers(node: Node) {
            node.recursiveChildren("BaseID").forEach {
                it.attributeNode("NameQualifier")?.let {
                    CommonDataTypeVerifier.verifyStringValue(it)
                }

                it.attributeNode(SP_NAME_QUALIFIER)?.let {
                    CommonDataTypeVerifier.verifyStringValue(it)
                }
            }
        }

        /** 2.2.2 Complex Type NameIDType */
        fun verifyNameIDType(node: Node) {
            verifyIdNameQualifiers(node)
            node.attributeNode(FORMAT)?.let {
                CommonDataTypeVerifier.verifyUriValue(it)
            }

            node.attributeNode("SPProvidedID")?.let {
                CommonDataTypeVerifier.verifyStringValue(it)
            }
        }
    }

    /** 2.2 Name Identifiers */
    fun verify() {
        verifyIdentifiers()
    }

    /**
     * 2.2.1 Element <BaseID>
     * 2.2.3 Element <NameID>
     * 2.2.5 Element <Issuer>
     */
    private fun verifyIdentifiers() {
        node.recursiveChildren("BaseID").forEach { verifyIdNameQualifiers(it) }
        node.recursiveChildren("NameID").forEach { verifyNameIDType(it) }
        node.recursiveChildren("Issuer").forEach { verifyNameIDType(it) }
    }
}
