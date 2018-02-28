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
package org.codice.compliance.core

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.w3c.dom.Node

var ID : String = ""

/**
 * Verify response against the Core Spec document
 */
fun verifyCore(node: Node, id : String) {
    ID = id
    verifyCommonDataType(node)
    verifyAssertions(node)
    verifyProtocols(node)
    verifySignatureSyntaxAndProcessing(node)
    verifyGeneralConsiderations(node)
}

/**
 * Verify signatures against the Core Spec document
 *
 * 5 SAML and XML Signature Syntax and Processing
 * 5.4.1 Signing Formats and Algorithms
 */
fun verifySignatureSyntaxAndProcessing(node: Node) {
    val assertions = node.children("Assertion")
    assertions.forEach {
        val signatures = it.children("Signature")
        if (signatures.isEmpty())
            throw SAMLComplianceException.create("SAMLCore.5.4.1_a")

        if (it.attributes.getNamedItem("ID") == null)
        // todo - same for protocols
            throw SAMLComplianceException.create("SAMLCore.5.4.2_a")

        val references = signatures[0].allChildren("Reference")
        if (references.size != 1)
            throw SAMLComplianceException.create("SAMLCore.5.4.2_b1")

        if (references[0].attributes.getNamedItem("URI")?.textContent
                != "#" + it.attributes.getNamedItem("ID")?.textContent)
            throw SAMLComplianceException.create("SAMLCore.5.4.2_b")
    }
}

fun verifyGeneralConsiderations(node: Node) {
    // todo - Encrypted data and [E30]zero or more encrypted keys MUST replace the plaintext information
    // in the same location within the XML instance.

    val assertions = node.children("Assertion")
    val baseIds = node.children("BaseID")
    val nameIds = node.children("NameID")
    val attributes = node.children("Attribute")

    val elements = mutableListOf<Node>()
    elements.addAll(assertions)
    elements.addAll(baseIds)
    elements.addAll(nameIds)
    elements.addAll(attributes)

    elements.forEach {
        val encryptedData = it.allChildren("EncryptedData")
        if (encryptedData.isNotEmpty() &&
                encryptedData[0].attributes.getNamedItem("EncryptedData").textContent
                        != "http://www.w3.org/2001/04/xmlenc#Element")
            throw SAMLComplianceException.create("SAMLCore.6.1_b")
    }
}