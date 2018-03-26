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

import de.jupf.staticlog.Log
import io.kotlintest.matchers.shouldNotBe
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLSpecRefMessage.SAMLBindings_3_4_3_b1
import org.codice.compliance.SAMLSpecRefMessage.SAMLBindings_3_5_3_a
import org.codice.compliance.SAMLSpecRefMessage.SAMLBindings_3_5_3_b
import org.codice.compliance.SAMLSpecRefMessage.SAMLBindings_3_5_4_a
import org.codice.compliance.SAMLSpecRefMessage.SAMLBindings_3_5_5_2_a
import org.codice.compliance.SAMLSpecRefMessage.SAMLProfiles_4_1_4_5
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.prettyPrintXml
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.MAX_RELAYSTATE_LEN
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.compliance.utils.decorators.IdpPostResponseDecorator
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.sign.Decoder

class PostBindingVerifier(private val response: IdpPostResponseDecorator) {
    /**
     * Verify the response for a post binding
     */
    fun verify() {
        decodeAndVerify()
        verifySsoPost()
        verifyPostRelayState()
        verifyPostDestination()
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the post binding rules in the binding spec
     * 3.5.4 Message Encoding
     */
    private fun decodeAndVerify() {
        val samlResponse = response.samlResponse
        val decodedMessage: String
        try {
            decodedMessage = Decoder.decodePostMessage(samlResponse)
        } catch (exception: Decoder.DecoderException) {
            throw SAMLComplianceException.create(SAMLBindings_3_5_4_a, message = "The SAML response could not be base64 decoded.", cause = exception)
        }

        decodedMessage shouldNotBe null
        Log.debugWithSupplier { decodedMessage.prettyPrintXml() }
        response.decodedSamlResponse = decodedMessage
    }

    /**
     * Checks POST-specific rules from SSO profile spec
     * 4.1.4.5 POST-Specific Processing Rules
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

    /**
     * Verifies the destination is correct according to the post binding rules in the binding spec
     * 3.5.5.2 Security Considerations
     */
    private fun verifyPostDestination() {
        val destination = response.responseDom.attributes.getNamedItem("Destination")?.nodeValue
        val signatures = response.responseDom.allChildren("Signature")

        if (signatures.isNotEmpty() && destination != acsUrl[HTTP_POST]) {
            throw SAMLComplianceException.createWithPropertyNotEqualMessage(
                    SAMLBindings_3_5_5_2_a,
                    "Destination",
                    destination,
                    acsUrl[HTTP_POST])
        }
    }
}
