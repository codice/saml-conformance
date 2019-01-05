/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.core.assertions

import org.codice.compliance.attributeNode
import org.codice.compliance.recursiveChildren
import org.codice.compliance.report.Report.Section.CORE_2_2
import org.codice.compliance.utils.FORMAT
import org.codice.compliance.utils.SP_NAME_QUALIFIER
import org.codice.compliance.verification.core.CommonDataTypeVerifier
import org.w3c.dom.Node

internal class NameIdentifierVerifier(val node: Node) {

    /** 2.2 Name Identifiers */
    fun verify() {
        CORE_2_2.start()
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

    /** 2.2.1 Element <BaseID> */
    private fun verifyIdNameQualifiers(node: Node) {
        node.attributeNode("NameQualifier")?.let {
            CommonDataTypeVerifier.verifyStringValue(it)
        }

        node.attributeNode(SP_NAME_QUALIFIER)?.let {
            CommonDataTypeVerifier.verifyStringValue(it)
        }
    }

    /** 2.2.2 Complex Type NameIDType */
    private fun verifyNameIDType(node: Node) {
        verifyIdNameQualifiers(node)
        node.attributeNode(FORMAT)?.let {
            CommonDataTypeVerifier.verifyUriValue(it)
        }

        node.attributeNode("SPProvidedID")?.let {
            CommonDataTypeVerifier.verifyStringValue(it)
        }
    }
}
