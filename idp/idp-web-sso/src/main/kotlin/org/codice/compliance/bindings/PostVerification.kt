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
package org.codice.compliance.bindings

import org.codice.compliance.RELAY_STATE
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.children
import org.w3c.dom.Node
import java.io.UnsupportedEncodingException
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * Verify the response for a post binding
 */
fun verifyPost(responseDomElement: Node, parsedResponse: Map<String, String>, givenRelayState: Boolean) {
    verifySsoPost(responseDomElement)
    parsedResponse["RelayState"]?.let { verifyPostRelayState(it, givenRelayState) }
}

/**
 * Checks POST-specific rules from SSO profile spec
 *
 * @param response - Response node
 */
fun verifySsoPost(response: Node) {
    if (response.children("Signature").isEmpty()
            || response.children("Assertion").any { it.children("Signature").isEmpty() })
        throw SAMLComplianceException.create("10") //If the HTTP POST binding is used to deliver the <Response>, [E26]each assertion MUST be protected by a digital signature. This can be accomplished by signing each individual <Assertion> element or by signing the <Response> element.
}

/**
 * Verifies the relay state according to the post binding rules in the binding spec
 */
fun verifyPostRelayState(relayState: String, givenRelayState: Boolean) {
    // if relay state is greater than 80 bytes
    if (relayState.toByteArray().size > 80) {
        throw SAMLComplianceException.create("SAMLBindings.3.5.3_a")
    }

    if (givenRelayState) {
        // if relay states do not match
        if (relayState != RELAY_STATE) {
            throw SAMLComplianceException.create("SAMLBindings.3.5.3_b1")
        }
    }
}