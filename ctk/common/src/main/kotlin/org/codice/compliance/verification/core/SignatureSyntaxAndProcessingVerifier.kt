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
import org.codice.compliance.report.Report
import org.codice.compliance.Section.CORE_5_4
import org.codice.compliance.utils.ID
import org.w3c.dom.Node

class SignatureSyntaxAndProcessingVerifier(private val node: Node) {

    /** 5 SAML and XML Signature Syntax and Processing */
    fun verify() {
        CORE_5_4.start()
        verifySignatureSyntaxAndProcessing()
    }

    /** 5.4.2 References */
    private fun verifySignatureSyntaxAndProcessing() {
        node.recursiveChildren(SSOConstants.SIGNATURE).forEach {
            val references = it.recursiveChildren("Reference")
            if (references.size != 1) {
                Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_5_4_2_a,
                        message = "A signature needs to have exactly one Reference, " +
                                "${references.size} found.",
                        node = node))
            }

            val uriValue = references[0].attributeText("URI")
            if (uriValue == null) {
                Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_5_4_2_a,
                        message = "URI attribute not found.",
                        node = node))
                return
            }

            val formattedId = "#${it.parentNode.attributeText(ID)}"
            if (uriValue != formattedId) {
                Report.addExceptionMessage(SAMLComplianceException.createWithPropertyMessage(
                        SAMLCore_5_4_2_a,
                        property = "URI",
                        actual = uriValue,
                        expected = formattedId,
                        node = node))
            }
        }
    }
}
