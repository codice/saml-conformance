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
import org.apache.cxf.rs.security.saml.sso.SSOConstants.RELAY_STATE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLSpecRefMessage.SAMLBindings_3_5_3_a
import org.codice.compliance.SAMLSpecRefMessage.SAMLBindings_3_5_3_b
import org.codice.compliance.SAMLSpecRefMessage.SAMLBindings_3_5_4_a1
import org.codice.compliance.SAMLSpecRefMessage.SAMLBindings_3_5_4_a2
import org.codice.compliance.SAMLSpecRefMessage.SAMLBindings_3_5_4_b1
import org.codice.compliance.SAMLSpecRefMessage.SAMLBindings_3_5_4_c
import org.codice.compliance.SAMLSpecRefMessage.SAMLBindings_3_5_4_d1
import org.codice.compliance.SAMLSpecRefMessage.SAMLBindings_3_5_4_d2
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
        verifyNoNulls()
        decodeAndVerify()
        verifyPostSSO()
        verifyPostRelayState()
        verifyPostDestination()
        verifyPostForm()
    }

    /**
     * Verifies the presence of post forms and values according to the post binding rules in the binding spec
     * 3.5.4 Message Encoding
     */
    private fun verifyNoNulls() {
        with(response) {
            if (isResponseFormNull || isSamlResponseFormNull) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_a2,
                        SAMLBindings_3_5_4_b1,
                        message = "The form containing the SAMLResponse from control could not be found.")
            }
            if (isRelayStateGiven && isRelayStateFormNull) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_c,
                        message = "The RelayState form control could not be found.")
            }
            if (samlResponse == null) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_a2,
                        SAMLBindings_3_5_4_b1,
                        message = "The SAMLResponse within the SAMLResponse form control could not be found.")
            }
            if (isRelayStateGiven && relayState == null) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_3_b,
                        SAMLBindings_3_5_4_c,
                        message = "The RelayState within the RelayState form control could not be found.")
            }
        }
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
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a1,
                    message = "The SAML response could not be base64 decoded.",
                    cause = exception)
        }

        decodedMessage shouldNotBe null
        Log.debugWithSupplier { decodedMessage.prettyPrintXml() }
        response.decodedSamlResponse = decodedMessage
    }

    /**
     * Checks POST-specific rules from SSO profile spec
     * 4.1.4.5 POST-Specific Processing Rules
     */
    private fun verifyPostSSO() {
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

        if (!givenRelayState && relayState == null) {
            return
        }

        if (relayState.toByteArray().size > MAX_RELAYSTATE_LEN)
            throw SAMLComplianceException.createWithPropertyMessage(
                    code = SAMLBindings_3_5_3_a,
                    property = RELAY_STATE,
                    actual = relayState)

        if (givenRelayState) {
            if (relayState != EXAMPLE_RELAY_STATE) {
                throw SAMLComplianceException.createWithPropertyMessage(
                        code = SAMLBindings_3_5_3_b,
                        property = RELAY_STATE,
                        actual = relayState,
                        expected = EXAMPLE_RELAY_STATE)
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
            throw SAMLComplianceException.createWithPropertyMessage(
                    code = SAMLBindings_3_5_5_2_a,
                    property = "Destination",
                    actual = destination,
                    expected = acsUrl[HTTP_POST])
        }
    }

    /**
     * Verifies the form carrying the SAMLRequest was properly formatted according to teh post binding rules in the binding spec
     * 3.5.4 Message Encoding
     */
    // TODO refactor this method and response objects so we can show values in the errors
    private fun verifyPostForm() {
        with(response) {
            if (!isFormActionCorrect) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_d1,
                        message = "The form \"action\" is incorrect.")
            }
            if (!isFormMethodCorrect) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_d2,
                        message = "The form \"method\" is incorrect.")
            }
            if (!isSamlResponseNameCorrect) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_b1,
                        message = "The SAMLResponse form control was incorrectly named.")
            }
            if (!isSamlResponseHidden) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_a2,
                        message = "The SAMLResponse form control was not hidden.")
            }
            if (!isRelayStateNameCorrect) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_c,
                        message = "The RelayState form control was incorrectly named.")
            }
            if (!isRelayStateHidden) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_c,
                        message = "The RelayState form control was not hidden.")
            }
        }
    }
}
