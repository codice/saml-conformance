/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.profile

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_4_4_3_3_a
import org.codice.compliance.SAMLProfiles_4_4_3_5_a
import org.codice.compliance.SAMLProfiles_4_4_4_1_a
import org.codice.compliance.SAMLProfiles_4_4_4_1_b
import org.codice.compliance.SAMLProfiles_4_4_4_2_a
import org.codice.compliance.SAMLProfiles_4_4_4_2_b
import org.codice.compliance.utils.LOGOUT_REQUEST
import org.codice.compliance.utils.LOGOUT_RESPONSE
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.verification.core.SubjectComparisonVerifier
import org.w3c.dom.Node

class SingleLogoutProfileVerifier(private val samlLogoutNode: NodeDecorator) {

    fun verifyLogoutRequest(ssoResponseDom: Node) {
        if (samlLogoutNode.localName != LOGOUT_REQUEST)
            throw SAMLComplianceException.create(SAMLProfiles_4_4_3_3_a,
                    message = "The IdP did not send a Logout Request to relevant " +
                            "session participants.",
                    node = samlLogoutNode)

        if (!samlLogoutNode.isSigned)
            throw SAMLComplianceException.create(SAMLProfiles_4_4_4_1_b,
                    message = "The Logout Request was not signed.",
                    node = samlLogoutNode)

        ProfilesVerifier.verifyIssuer(samlLogoutNode, SAMLProfiles_4_4_4_1_a)
        SubjectComparisonVerifier(ssoResponseDom)
                .verifyIdsMatchSLO(samlLogoutNode)
    }

    fun verifyLogoutResponse() {
        if (samlLogoutNode.localName != LOGOUT_RESPONSE)
            throw SAMLComplianceException.create(SAMLProfiles_4_4_3_5_a,
                    message = "The IdP did not send a Logout Response to the original " +
                            "session participant.",
                    node = samlLogoutNode)

        if (!samlLogoutNode.isSigned)
            throw SAMLComplianceException.create(SAMLProfiles_4_4_4_2_b,
                    message = "The Logout Response was not signed.",
                    node = samlLogoutNode)

        ProfilesVerifier.verifyIssuer(samlLogoutNode, SAMLProfiles_4_4_4_2_a)
    }
}
