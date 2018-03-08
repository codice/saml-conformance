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

import org.apache.cxf.rs.security.saml.sso.SSOConstants.RELAY_STATE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.w3c.dom.Node

class PostVerifier(responseDom: Node, parsedResponse: Map<String, String>, givenRelayState: Boolean): BindingVerifier(responseDom, parsedResponse, givenRelayState) {
    /**
     * Verify the response for a post binding
     */
    override fun verifyBinding() {
        verifySsoPost(responseDom)
        verifyPostRelayState(parsedResponse[RELAY_STATE], givenRelayState)
    }

    /**
     * Checks POST-specific rules from SSO profile spec
     * 4.1.4.5 POST-Specific Processing Rules
     *
     * @param response - Response node
     */
    fun verifySsoPost(response: Node) {
        if (response.children(SIGNATURE).isEmpty()
                || response.children("Assertion").any { it.children(SIGNATURE).isEmpty() })
            throw SAMLComplianceException.create("SAMLProfiles.4.1.4.5_a")
    }

    /**
     * Verifies the relay state according to the post binding rules in the binding spec
     * 3.5.3 RelayState
     */
    fun verifyPostRelayState(relayState: String?, givenRelayState: Boolean) {
        if (relayState == null) {
            if (givenRelayState) {
                throw SAMLComplianceException.create("GeneralRelayState_a", "SAMLBindings.3.4.3_b1")
            }
            return
        }
        if (relayState.toByteArray().size > 80)
            throw SAMLComplianceException.create("SAMLBindings.3.5.3_a1")

        if (givenRelayState) {
            if (relayState != EXAMPLE_RELAY_STATE) throw SAMLComplianceException.create("GeneralRelayState_b", "SAMLBindings.3.5.3_b1")
        }
    }
}