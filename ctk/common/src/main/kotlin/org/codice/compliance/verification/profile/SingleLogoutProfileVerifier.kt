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

import org.codice.compliance.SAMLProfiles_4_4_4_1_a
import org.codice.compliance.SAMLProfiles_4_4_4_1_c
import org.codice.compliance.SAMLProfiles_4_4_4_2_a
import org.codice.compliance.utils.LOGOUT_REQUEST
import org.codice.compliance.utils.LOGOUT_RESPONSE
import org.codice.compliance.utils.NodeWrapper
import org.codice.compliance.verification.core.SubjectComparisonVerifier
import org.opensaml.saml.saml2.core.AuthnRequest

class SingleLogoutProfileVerifier(samlLogoutNodeWrapper: NodeWrapper,
                                  private val authnRequest: AuthnRequest? = null) {
    private val samlLogoutNode = samlLogoutNodeWrapper.node

    fun verify() {
        if (samlLogoutNode.localName == LOGOUT_REQUEST) {
            ProfilesVerifier.verifyIssuer(samlLogoutNode, SAMLProfiles_4_4_4_1_a)
            SubjectComparisonVerifier(samlLogoutNode, authnRequest)
                    .verifySubjectsMatchAuthnRequest(SAMLProfiles_4_4_4_1_c)
        }

        if (samlLogoutNode.localName == LOGOUT_RESPONSE)
            ProfilesVerifier.verifyIssuer(samlLogoutNode, SAMLProfiles_4_4_4_2_a)
    }
}
