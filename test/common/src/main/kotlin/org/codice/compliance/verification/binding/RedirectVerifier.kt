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

import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLSpecRefMessage.*
import org.codice.compliance.children
import org.codice.compliance.saml.plugin.IdpRedirectResponse
import org.codice.compliance.utils.TestCommon.Companion.ACS_URL
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.idpMetadata
import org.codice.security.sign.SimpleSign
import org.codice.security.sign.SimpleSign.SignatureException.SigErrorCode
import java.io.UnsupportedEncodingException
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

class RedirectVerifier(val response: IdpRedirectResponse) : BindingVerifier() {
    /**
     * Verify the response for a redirect binding
     */
    override fun verifyBinding() {
        verifyRequestParam()
        verifyNoXMLSig()
        verifyRedirectRelayState()
        response.signature?.let {
            verifyRedirectSignature()
            verifyRedirectDestination()
        }
    }

    /**
     * Verifies the redirect response has a SAMLResponse query param according to the redirect binding rules in the binding spec
     * 3.4.4.1 DEFLATE ENCODING
     */
    private fun verifyRequestParam() {
        if (response.samlResponse == null) {
            throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_b2, message = "No SAMLResponse found.")
        }
    }

    /**
     * Verifies the redirect response has no XMLSig in the url according to the redirect binding rules in the binding spec
     * 3.4.4.1 DEFLATE ENCODING
     */
    private fun verifyNoXMLSig() {
        if (response.responseDom.children("Signature").isNotEmpty()) {
            throw SAMLComplianceException.create(SAMLBindings_3_4_4_1, message = "Signature element found.")
        }
    }

    /**
     * Verifies the Signature and SigAlg according to the redirect binding rules in the binding spec
     * 3.4.4.1 DEFLATE Encoding
     */
    private fun verifyRedirectSignature() {

        try {
            if (!SimpleSign().validateSignature(
                            SAML_RESPONSE,
                            response.samlResponse,
                            response.relayState,
                            response.signature,
                            response.sigAlg,
                            idpMetadata.signingCertificate)) {
                throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_e, message = "Signature does not match payload.")
            }
        } catch (e: SimpleSign.SignatureException) {
            when (e.errorCode) {
                SigErrorCode.INVALID_CERTIFICATE -> throw SAMLComplianceException.create(SAMLBindings_3_1_2_1, message = "The certificate was invalid.", cause = e)
                SigErrorCode.SIG_ALG_NOT_PROVIDED -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_d1, message = "Signature Algorithm not found.", cause = e)
                SigErrorCode.SIGNATURE_NOT_PROVIDED -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_f2, message = "Signature not found.", cause = e)
                SigErrorCode.INVALID_URI -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_d2, message = "The Signature algorithm named ${response.sigAlg} is unknown.", cause = e)
                SigErrorCode.LINEFEED_OR_WHITESPACE -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_f1, message = "Whitespace was found in the Signature.", cause = e)
                else -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_e, message = "Signature does not match payload.", cause = e)
            }
        }
    }

    /**
     * Verifies the relay state according to the redirect binding rules in the binding spec
     * 3.4.3 RelayState
     * 3.4.4.1 DEFLATE Encoding
     */
    private fun verifyRedirectRelayState() {
        val encodedRelayState = response.relayState
        val givenRelayState = response.isRelayStateGiven

        if (encodedRelayState == null) {
            if (givenRelayState) {
                throw SAMLComplianceException.create(SAMLBindings_3_4_3_b1, message = "RelayState not found.")
            }
            return
        }

        val decodedRelayState: String
        try {
            decodedRelayState = URLDecoder.decode(encodedRelayState, StandardCharsets.UTF_8.name())
        } catch (e: UnsupportedEncodingException) {
            throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_c1, message = "RelayState could not be URL decoded.", cause = e)
        }

        if (decodedRelayState.toByteArray().size > 80) {
            throw SAMLComplianceException.create(SAMLBindings_3_4_3_a, message = "RelayState value of $decodedRelayState was longer than 80 bytes.")
        }

        if (givenRelayState) {
            if (decodedRelayState != EXAMPLE_RELAY_STATE) {
                if (encodedRelayState == EXAMPLE_RELAY_STATE) {
                    throw SAMLComplianceException.createWithPropertyInvalidMessage(SAMLBindings_3_4_4_1_c1, "RelayState", encodedRelayState)
                }
                throw SAMLComplianceException.createWithPropertyNotEqualMessage(SAMLBindings_3_4_3_b1, "RelayState", decodedRelayState, EXAMPLE_RELAY_STATE)
            }
        }
    }

    /**
     * Verifies the destination is correct according to the redirect binding rules in the bindinc spec
     * 3.4.5.2 Security Considerations
     */
    private fun verifyRedirectDestination() {
        val destination = response.responseDom.attributes.getNamedItem("Destination")?.nodeValue
        if (destination != ACS_URL) {
            throw SAMLComplianceException.createWithPropertyNotEqualMessage(SAMLBindings_3_4_5_2_a1, "Destination", destination, ACS_URL)
        }
    }
}