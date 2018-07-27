/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.core.responses

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_7_3_2_b
import org.codice.compliance.SAMLCore_3_7_3_2_d
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.utils.STATUS
import org.codice.compliance.utils.STATUS_CODE
import org.codice.compliance.verification.core.ResponseVerifier
import org.codice.security.saml.SamlProtocol
import org.opensaml.saml.saml2.core.LogoutRequest

class CoreLogoutResponseProtocolVerifier(logoutRequest: LogoutRequest,
                                         private val samlResponse: NodeDecorator,
                                         binding: SamlProtocol.Binding,
                                         private val expectedSecondLevelStatusCode: String? = null)
    : ResponseVerifier(logoutRequest, samlResponse, binding) {

    override fun verify() {
        super.verify()
        verifySecondaryStatusCode()
    }

    private fun verifySecondaryStatusCode() {
        val secondaryStatusCode = samlResponse.children(STATUS)
                .flatMap { it.children(STATUS_CODE) }
                .firstOrNull()
                ?.children(STATUS_CODE)
                ?.firstOrNull()
                ?.attributeText("Value")

        if (expectedSecondLevelStatusCode != null
                && secondaryStatusCode != expectedSecondLevelStatusCode)
            throw SAMLComplianceException.create(SAMLCore_3_7_3_2_b,
                    SAMLCore_3_7_3_2_d,
                    message = "The status code of $expectedSecondLevelStatusCode was not found",
                    node = samlResponse)
    }
}
