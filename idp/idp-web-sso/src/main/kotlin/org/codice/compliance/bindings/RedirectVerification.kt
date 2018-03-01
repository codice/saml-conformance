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
import org.codice.compliance.idpMetadata
import org.codice.security.saml.IdpMetadata
import org.w3c.dom.Node
import java.io.UnsupportedEncodingException
import java.net.URLDecoder
import java.net.URLEncoder
import java.nio.charset.StandardCharsets
import org.codice.security.sign.SimpleSign

/**
 * Verify the response for a redirect binding
 */
fun verifyRedirect(responseDomElement: Node, parsedResponse : Map<String, String>, givenRelayState: Boolean) {
    parsedResponse["RelayState"]?.let { verifyRedirectRelayState(it, givenRelayState) }
    parsedResponse["Signature"]?.let { verifyRedirectSignature(it, parsedResponse) }
    parsedResponse["SigAlg"]?.let { verifyRedirectSigAlg(it) }
}

/**
 * Verifies the signature algorithm according to the redirect binding rules in the binding spec
 */
fun verifyRedirectSigAlg(sigAlg: String) {

}

/**
 * Verifies the signature according to the redirect binding rules in the binding spec
 */
fun verifyRedirectSignature(signature: String, parsedResponse: Map<String, String>) {
    // set up query params that were signed
    val queryParams = StringBuilder()
    parsedResponse["SAMLResponse"]?.let {
        queryParams.append("SAMLResponse=")
        queryParams.append(it)
        queryParams.append("&")
    }
    parsedResponse["RelayState"]?.let {
        queryParams.append("RelayState=")
        queryParams.append(it)
        queryParams.append("&")
    }
    parsedResponse["SigAlg"]?.let {
        queryParams.append("SigAlg=")
        queryParams.append(it)
    }

    val verify = SimpleSign().validateSignature(
            queryParams.toString(),
            signature,
            parsedResponse["SigAlg"],
            idpMetadata.signingCertificate
    )

    if (!verify) {
        throw SAMLComplianceException.create("SAMLBindings.3.4.4.1_d")
    }
}

/**
 * Verifies the relay state according to the redirect binding rules in the binding spec
 */
fun verifyRedirectRelayState(encodedRelayState: String, givenRelayState: Boolean) {
    val decodedRelayState : String

    // try to URL decode relay state
    try {
        decodedRelayState = URLDecoder.decode(encodedRelayState, StandardCharsets.UTF_8.name())
    } catch (e : UnsupportedEncodingException) {
        throw SAMLComplianceException.create("SAMLBindings.3.4.4.1_c1")
    }

    // if relay state is greater than 80 bytes
    if (decodedRelayState.toByteArray().size > 80) {
        throw SAMLComplianceException.create("SAMLBindings.3.4.3_a")
    }

    if (givenRelayState) {
        if (decodedRelayState != RELAY_STATE) {
            // if relayState is not url encoded
            if (encodedRelayState == RELAY_STATE) {
                throw SAMLComplianceException.create("SAMLBindings.3.4.4.1_c1")
            }
            // if relayState is not exactly the same
            throw SAMLComplianceException.create("SAMLBindings.3.4.3_b1")
        }
    }
}