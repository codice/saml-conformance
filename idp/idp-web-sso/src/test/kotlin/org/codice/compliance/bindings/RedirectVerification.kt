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
import org.w3c.dom.Node
import java.net.URLEncoder
import java.nio.charset.StandardCharsets

/**
 * Verify the response for a redirect binding
 */
fun verifyRedirect(response: Node, parsedResponse: Map<String, String>) {
    parsedResponse["RelayState"]?.let { verifyRedirectRelayState(it) }
    parsedResponse["Signature"]?.let { verifyRedirectSignature(it) }
    parsedResponse["SigAlg"]?.let { verifyRedirectSigAlg(it) }
}

/**
 * Verifies the signature algorithm according to the redirect binding rules in the binding spec
 */
fun verifyRedirectSigAlg(sigAlg: String) {

}

/**
 * Verifies the signature according to the post redirect rules in the binding spec
 */
fun verifyRedirectSignature(signature: String) {

}

/**
 * Verifies the relay state according to the post redirect rules in the binding spec
 */
fun verifyRedirectRelayState(relayState: String) {
    if (relayState != URLEncoder.encode(RELAY_STATE, StandardCharsets.UTF_8.name())) {
        if (relayState == RELAY_STATE) {
            // relay state not encoded
            throw SAMLComplianceException.create("SAMLBindings.3.4.4.1_c1")
        }
        // relay states not identical
        throw SAMLComplianceException.create("SAMLBindings.3.4.3_a")
    }
}