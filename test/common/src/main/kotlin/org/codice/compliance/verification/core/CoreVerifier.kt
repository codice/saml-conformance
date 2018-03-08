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

import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon.Companion.ELEMENT
import org.w3c.dom.Node

class CoreVerifier(val node: Node) {
    /**
     * Verify response against the Core Spec document
     */
    fun verify() {
        verifyCommonDataType(node)

        val samlAssertionsVerifier = SamlAssertionsVerifier(node)
        samlAssertionsVerifier.verify()

        verifySignatureSyntaxAndProcessing(node)
        verifyGeneralConsiderations(node)
    }

    /**
     * Verify signatures against the Core Spec document
     *
     * 5 SAML and XML Signature Syntax and Processing
     * 5.4.1 Signing Formats and Algorithms
     */
    private fun verifySignatureSyntaxAndProcessing(node: Node) {
        node.children("Assertion").forEach {
            val signatures = it.children(SIGNATURE)
            if (signatures.isEmpty())
                throw SAMLComplianceException.create("SAMLCore.5.4.1_a")

            if (it.attributes.getNamedItem("ID") == null)
                throw SAMLComplianceException.create("SAMLCore.5.4.2_a")

            signatures.forEach {
                val references = it.allChildren("Reference")
                if (references.size != 1)
                    throw SAMLComplianceException.create("SAMLCore.5.4.2_b1")

                if (references[0].attributes.getNamedItem("URI")?.textContent
                        != "#" + it.parentNode.attributes.getNamedItem("ID")?.textContent)
                    throw SAMLComplianceException.create("SAMLCore.5.4.2_b")
            }
        }
    }

    private fun verifyGeneralConsiderations(node: Node) {
        // todo - Encrypted data and [E30]zero or more encrypted keys MUST replace the plaintext information
        // in the same location within the XML instance.

        val elements = mutableListOf<Node>()
        elements.addAll(node.children("Assertion"))
        elements.addAll(node.children("BaseID"))
        elements.addAll(node.children("NameID"))
        elements.addAll(node.children("Attribute"))

        elements.forEach {
            val encryptedData = it.allChildren("EncryptedData")
            if (encryptedData.isNotEmpty() &&
                    encryptedData[0].attributes.getNamedItem("EncryptedData").textContent
                    != ELEMENT)
                throw SAMLComplianceException.create("SAMLCore.6.1_b")
        }
    }
}
