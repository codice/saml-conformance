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

import com.sun.org.apache.xml.internal.resolver.readers.ExtendedXMLCatalogReader
import org.apache.cxf.rs.security.saml.sso.SSOConstants.*
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLComplianceExceptionMessage.*
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon.Companion.ACS_URL
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.idpMetadata
import org.codice.security.sign.SimpleSign
import org.codice.security.sign.SimpleSign.SignatureException.SigErrorCode
import org.w3c.dom.Node
import java.io.UnsupportedEncodingException
import java.net.URLDecoder
import java.nio.charset.StandardCharsets

class RedirectVerifier(responseDom: Node, parsedResponse: Map<String, String>, givenRelayState: Boolean): BindingVerifier(responseDom, parsedResponse, givenRelayState) {
    /**
     * Verify the response for a redirect binding
     */
    override fun verifyBinding() {
        verifyRequestParam(parsedResponse[SAML_RESPONSE])
        verifyNoXMLSig(responseDom)
        verifyRedirectRelayState(parsedResponse[RELAY_STATE], givenRelayState)
        parsedResponse[SIGNATURE]?.let {
            verifyRedirectSignature(it, parsedResponse[SAML_RESPONSE], parsedResponse[RELAY_STATE], parsedResponse[SIG_ALG])
            verifyRedirectDestination(responseDom)
        }
    }

    /**
     * Verifies the redirect response has a SAMLResponse query param according to the redirect binding rules in the binding spec
     * 3.4.4.1 DEFLATE ENCODING
     */
    fun verifyRequestParam(SAMLResponse: String?) {
        if (SAMLResponse == null) {
            throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_b2)
        }
    }

    /**
     * Verifies the redirect response has no XMLSig in the url according to the redirect binding rules in the binding spec
     * 3.4.4.1 DEFLATE ENCODING
     */
    fun verifyNoXMLSig(node: Node) {
        if (node.children("Signature").isNotEmpty()) {
            throw SAMLComplianceException.create(SAMLBindings_3_4_4_1)
        }
    }

    /**
     * Verifies the Signature and SigAlg according to the redirect binding rules in the binding spec
     * 3.4.4.1 DEFLATE Encoding
     */
    fun verifyRedirectSignature(signature: String, samlResponse: String?, relayState: String?, sigAlg: String?) {
        val verify: Boolean
        try {
            if (!SimpleSign().validateSignature(
                            SAML_RESPONSE,
                            samlResponse,
                            relayState,
                            signature,
                            sigAlg,
                            idpMetadata.signingCertificate)) {
                throw SAMLComplianceException.create(GeneralSignature_b, SAMLBindings_3_4_4_1_e)
            }
        } catch (e: SimpleSign.SignatureException) {
            when (e.errorCode) {
                SigErrorCode.INVALID_CERTIFICATE -> throw SAMLComplianceException.create(GeneralCertificate_a, SAMLBindings_3_1_2_1, cause = e)
                SigErrorCode.SIG_ALG_NOT_PROVIDED -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_d1, cause = e)
                SigErrorCode.SIGNATURE_NOT_PROVIDED -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_f2, cause = e)
                SigErrorCode.INVALID_URI -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_d2, cause = e)
                SigErrorCode.LINEFEED_OR_WHITESPACE -> throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_f1, cause = e)
                else -> throw SAMLComplianceException.create(GeneralSignature_a, SAMLBindings_3_4_4_1_e, cause = e)
            }
        }
    }

    /**
     * Verifies the relay state according to the redirect binding rules in the binding spec
     * 3.4.3 RelayState
     * 3.4.4.1 DEFLATE Encoding
     */
    fun verifyRedirectRelayState(encodedRelayState: String?, givenRelayState: Boolean) {

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
    fun verifyRedirectDestination(responseDomElement: Node) {
        val destination = responseDomElement.attributes.getNamedItem("Destination")?.nodeValue
        if (destination != ACS_URL) {
            throw SAMLComplianceException.createWithPropertyNotEqualMessage(SAMLBindings_3_4_5_2_a1, "Destination", destination, ACS_URL)
        }
    }
}