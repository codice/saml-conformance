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

/**
 * Verify response against the Core Spec document
 */
fun verifyCore(response: Node) {
    verifyAssertions(response)
    verifyProtocols(response)
    verifySignatureSyntaxAndProcessing(response)
}

/**
 * Verify signatures against the Core Spec document
 *
 * 5 SAML and XML Signature Syntax and Processing
 * 5.4.1 Signing Formats and Algorithms
 */
fun verifySignatureSyntaxAndProcessing(response: Node) {
    val assertions = response.children("Assertion")
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