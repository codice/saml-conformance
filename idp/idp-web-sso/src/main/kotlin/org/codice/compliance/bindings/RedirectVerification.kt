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
import org.codice.compliance.idpMetadata
import org.codice.security.sign.SimpleSign
import org.w3c.dom.Node
import java.io.UnsupportedEncodingException
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

/**
 * Verify the response for a redirect binding
 */
fun verifyRedirect(responseDomElement: Node, parsedResponse: Map<String, String>, givenRelayState: Boolean) {
    verifyRequestParam(parsedResponse["SAMLResponse"])
    verifyNoXMLSig(responseDomElement)
    verifyRedirectRelayState(parsedResponse["RelayState"], givenRelayState)
    parsedResponse["Signature"]?.let { verifyRedirectSignature(it, parsedResponse["SAMLResponse"], parsedResponse["RelayState"], parsedResponse["SigAlg"]) }
}

/**
 * Verifies the redirect response has a SAMLResponse query param according to the redirect binding rules in the binding spec
 * 3.4.4.1 DEFLATE ENCODING
 */
fun verifyRequestParam(SAMLResponse: String?) {
    if (SAMLResponse == null) {
        throw SAMLComplianceException.create("SAMLBindings.3.4.4.1.b2")
    }
}

/**
 * Verifies the redirect response has no XMLSig in the url according to the redirect binding rules in the binding spec
 * 3.4.4.1 DEFLATE ENCODING
 */
fun verifyNoXMLSig(node: Node) {
    if (node.children("Signature").isNotEmpty()) {
        throw SAMLComplianceException.create("SAMLBindings.3.4.4.1")
    }
}

/**
 * Verifies the Signature and SigAlg according to the redirect binding rules in the binding spec
 * 3.4.4.1 DEFLATE Encoding
 */
fun verifyRedirectSignature(signature: String, samlResponse: String?, relayState: String?, sigAlg: String?) {
    val verify: Boolean
    try {
        verify = SimpleSign().validateSignature(
                "SAMLResponse",
                samlResponse,
                relayState,
                signature,
                sigAlg,
                idpMetadata.signingCertificate)
    } catch (e: SimpleSign.SignatureException) {
        when (e.message) {
            "SigAlg not provided" -> throw SAMLComplianceException.create("SAMLBindings.3.4.4.1_d1")
            "Signature not provided" -> throw SAMLComplianceException.create("SAMLBindings.3.4.4.1_f2")
            "Invalid URI" -> throw SAMLComplianceException.create("SAMLBindings.3.4.4.1_d2")
            "Linefeed or Whitespace in decoded signature" -> throw SAMLComplianceException.create("SAMLBindings.3.4.4.1_f1")
            else -> throw SAMLComplianceException.create("GeneralSignature_a", "SAMLBindings.3.4.4.1_e")
        }
    }
    if (!verify)
        throw SAMLComplianceException.create("GeneralSignature_b", "SAMLBindings.3.4.4.1_e")
}

/**
 * Verifies the relay state according to the redirect binding rules in the binding spec
 * 3.4.3 RelayState
 * 3.4.4.1 DEFLATE Encoding
 */
fun verifyRedirectRelayState(encodedRelayState: String?, givenRelayState: Boolean) {

    if (encodedRelayState == null) {
        if (givenRelayState) {
            throw SAMLComplianceException.create("GeneralRelayState_a", "SAMLBindings.3.4.3_b1")
        }
        return
    }

    val decodedRelayState: String
    try {
        decodedRelayState = URLDecoder.decode(encodedRelayState, StandardCharsets.UTF_8.name())
    } catch (e: UnsupportedEncodingException) {
        throw SAMLComplianceException.create("SAMLBindings.3.4.4.1_c1")
    }

    if (decodedRelayState.toByteArray().size > 80) {
        throw SAMLComplianceException.create("SAMLBindings.3.4.3_a")
    }

    if (givenRelayState) {
        if (decodedRelayState != RELAY_STATE) {
            if (encodedRelayState == RELAY_STATE) {
                throw SAMLComplianceException.create("SAMLBindings.3.4.4.1_c1")
            }
            throw SAMLComplianceException.create("GeneralRelayState_b", "SAMLBindings.3.4.3_b1")
        }
    }
}