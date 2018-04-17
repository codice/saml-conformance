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

import org.apache.cxf.rs.security.saml.sso.SSOConstants
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_5_4_2_b
import org.codice.compliance.SAMLCore_5_4_2_b1
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.w3c.dom.Node

class SignatureSyntaxAndProcessingVerifier(private val node: Node) {

    /** 5 SAML and XML Signature Syntax and Processing */
    fun verify() {
        verifySignatureSyntaxAndProcessing()
    }

    /** 5.4.2 References */
    private fun verifySignatureSyntaxAndProcessing() {
        node.children(SSOConstants.SIGNATURE).forEach {
            val references = it.recursiveChildren("Reference")
            if (references.size != 1)
                throw SAMLComplianceException.create(SAMLCore_5_4_2_b1,
                        message = "A signature needs to have exactly one Reference, " +
                                "${references.size} found.",
                        node = node)

            val uriValue = references[0].attributeText("URI")
                    ?: throw SAMLComplianceException.create(SAMLCore_5_4_2_b1,
                            message = "URI attribute not found.",
                            node = node)

            val formattedId = "#${it.parentNode.attributeText("ID")}"
            if (uriValue != formattedId)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_5_4_2_b,
                        property = "URI",
                        actual = uriValue,
                        expected = formattedId,
                        node = node)
        }
    }
}
