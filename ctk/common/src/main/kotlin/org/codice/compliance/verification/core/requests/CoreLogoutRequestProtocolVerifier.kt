/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.core.requests

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_7_1_a
import org.codice.compliance.SAMLCore_3_7_3_2_e
import org.codice.compliance.attributeNode
import org.codice.compliance.report.Report
import org.codice.compliance.Section.CORE_3_7
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.verification.core.CommonDataTypeVerifier
import org.codice.compliance.verification.core.RequestVerifier
import org.codice.security.saml.SamlProtocol

class CoreLogoutRequestProtocolVerifier(
    private val samlRequest: NodeDecorator,
    binding: SamlProtocol.Binding
) : RequestVerifier(samlRequest, binding) {

    /** 3.7.1 Element <LogoutRequest>*/
    override fun verify() {
        CORE_3_7.start()
        verifyLogoutRequest()
        super.verify()
    }

    private fun verifyLogoutRequest() {
        samlRequest.attributeNode("Reason")?.let {
            CommonDataTypeVerifier.verifyUriValue(it, SAMLCore_3_7_1_a)
        }

        val notOnOrAfter = samlRequest.attributeNode("NotOnOrAfter")
        if (notOnOrAfter == null) {
            Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_3_7_3_2_e,
                    message = "The attribute NotOnOrAfter was not found.",
                    node = samlRequest))
        } else {
            CommonDataTypeVerifier.verifyDateTimeValue(notOnOrAfter)
        }
    }
}
