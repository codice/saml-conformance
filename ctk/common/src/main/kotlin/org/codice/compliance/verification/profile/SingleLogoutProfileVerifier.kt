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
import org.codice.compliance.utils.NodeWrapper
import org.codice.compliance.verification.core.SubjectComparisonVerifier
import org.w3c.dom.Node

class SingleLogoutProfileVerifier(private val samlLogoutNodeWrapper: NodeWrapper) {
    private val samlLogoutNode = samlLogoutNodeWrapper.node

    fun verifyLogoutRequest(ssoResponseDom: Node) {
        if (samlLogoutNode.localName != LOGOUT_REQUEST)
            throw SAMLComplianceException.create(SAMLProfiles_4_4_3_3_a,
                    message = "The IdP did not send a Logout Request to relevant " +
                            "session participants.",
                    node = samlLogoutNode)

        if (!samlLogoutNodeWrapper.isSigned)
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

        if (!samlLogoutNodeWrapper.isSigned)
            throw SAMLComplianceException.create(SAMLProfiles_4_4_4_2_b,
                    message = "The Logout Response was not signed.",
                    node = samlLogoutNode)

        ProfilesVerifier.verifyIssuer(samlLogoutNode, SAMLProfiles_4_4_4_2_a)
    }
}
