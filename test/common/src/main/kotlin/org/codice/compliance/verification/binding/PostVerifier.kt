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
package org.codice.compliance.verification.binding

import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLSpecRefMessage.*
import org.codice.compliance.children
import org.codice.compliance.saml.plugin.IdpPostResponse
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE

class PostVerifier(val response: IdpPostResponse) : BindingVerifier() {
    /**
     * Verify the response for a post binding
     */
    override fun verifyBinding() {
        verifySsoPost()
        verifyPostRelayState()
    }

    /**
     * Checks POST-specific rules from SSO profile spec
     * 4.1.4.5 POST-Specific Processing Rules
     *
     * @param response - Response node
     */
    private fun verifySsoPost() {
        if (response.responseDom.children(SIGNATURE).isEmpty()
                || response.responseDom.children("Assertion").any { it.children(SIGNATURE).isEmpty() })
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_5, message = "No digital signature found on the " +
                    "Response or Assertions.")
    }

    /**
     * Verifies the relay state according to the post binding rules in the binding spec
     * 3.5.3 RelayState
     */
    private fun verifyPostRelayState() {
        val relayState = response.relayState
        val givenRelayState = response.isRelayStateGiven

        if (relayState == null) {
            if (givenRelayState) {
                throw SAMLComplianceException.create(SAMLBindings_3_4_3_b1, message = "RelayState not found.")
            }
            return
        }
        if (relayState.toByteArray().size > MAX_RELAYSTATE_LEN)
            throw SAMLComplianceException.createWithPropertyInvalidMessage(SAMLBindings_3_5_3_a,
                    "RelayState",
                    relayState)

        if (givenRelayState) {
            if (relayState != EXAMPLE_RELAY_STATE) {
                throw SAMLComplianceException.createWithPropertyNotEqualMessage(SAMLBindings_3_5_3_b,
                        "RelayState",
                        relayState,
                        EXAMPLE_RELAY_STATE)
            }
        }
    }
}
