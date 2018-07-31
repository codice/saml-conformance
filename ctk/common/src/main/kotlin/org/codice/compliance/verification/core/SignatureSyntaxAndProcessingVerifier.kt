/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.core

import org.apache.cxf.rs.security.saml.sso.SSOConstants
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_5_4_2_a
import org.codice.compliance.attributeText
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.ID
import org.w3c.dom.Node

class SignatureSyntaxAndProcessingVerifier(private val node: Node) {

    /** 5 SAML and XML Signature Syntax and Processing */
    fun verify() {
        verifySignatureSyntaxAndProcessing()
    }

    /** 5.4.2 References */
    private fun verifySignatureSyntaxAndProcessing() {
        node.recursiveChildren(SSOConstants.SIGNATURE).forEach {
            val references = it.recursiveChildren("Reference")
            if (references.size != 1)
                throw SAMLComplianceException.create(SAMLCore_5_4_2_a,
                        message = "A signature needs to have exactly one Reference, " +
                                "${references.size} found.",
                        node = node)

            val uriValue = references[0].attributeText("URI")
                    ?: throw SAMLComplianceException.create(SAMLCore_5_4_2_a,
                            message = "URI attribute not found.",
                            node = node)

            val formattedId = "#${it.parentNode.attributeText(ID)}"
            if (uriValue != formattedId)
                throw SAMLComplianceException.createWithPropertyMessage(
                        SAMLCore_5_4_2_a,
                        property = "URI",
                        actual = uriValue,
                        expected = formattedId,
                        node = node)
        }
    }
}
