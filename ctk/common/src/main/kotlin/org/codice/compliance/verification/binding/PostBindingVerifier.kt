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
import org.codice.compliance.SAMLBindings_3_5_3_a
import org.codice.compliance.SAMLBindings_3_5_3_b
import org.codice.compliance.SAMLBindings_3_5_4_a1
import org.codice.compliance.SAMLBindings_3_5_4_a2
import org.codice.compliance.SAMLBindings_3_5_4_b1
import org.codice.compliance.SAMLBindings_3_5_4_c
import org.codice.compliance.SAMLBindings_3_5_4_d1
import org.codice.compliance.SAMLBindings_3_5_4_d2
import org.codice.compliance.SAMLBindings_3_5_5_2_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_4_1_4_5
import org.codice.compliance.attributeNode
import org.codice.compliance.children
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.IDP_ERROR_RESPONSE_REMINDER_MESSAGE
import org.codice.compliance.utils.TestCommon.Companion.MAX_RELAY_STATE_LEN
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.compliance.utils.decorators.IdpPostResponseDecorator
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.sign.Decoder
import kotlin.test.assertNotNull

class PostBindingVerifier(private val response: IdpPostResponseDecorator) : BindingVerifier() {

    /**
     * Verify the response for a post binding
     */
    override fun verify() {
        verifyHttpStatusCode(response.httpStatusCode)
        verifyNoNulls()
        decodeAndVerify()
        verifyPostSSO()
        if (response.isRelayStateGiven || response.relayState != null) {
            verifyPostRelayState()
        }
        verifyPostDestination()
        verifyPostForm()
    }

    /**
     * Verify an error response (Negative path)
     */
    override fun verifyError() {
        verifyHttpStatusCodeErrorResponse(response.httpStatusCode)
        verifyNoNullsErrorResponse()
        decodeAndVerifyErrorResponse()
    }

    /**
     * Verifies the presence of post forms and values according to the post binding rules in
     * the binding spec
     * 3.5.4 Message Encoding
     */
    private fun verifyNoNulls() {
        with(response) {
            if (isResponseFormNull || isSamlResponseFormNull) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_a2,
                        SAMLBindings_3_5_4_b1,
                        message = "The form containing the SAMLResponse from control could not be" +
                                "found.")
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
                        message = "The SAMLResponse within the SAMLResponse form control could " +
                                "not be found.")
            }
            if (isRelayStateGiven && relayState == null) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_3_b,
                        SAMLBindings_3_5_4_c,
                        message = "The RelayState within the RelayState form control could not" +
                                "be found.")
            }
        }
    }

    /**
     * Verifies the presence of post forms and values according to the post binding rules in
     * the binding spec (Negative path)
     * 3.5.4 Message Encoding
     */
    private fun verifyNoNullsErrorResponse() {
        with(response) {
            if (isResponseFormNull || isSamlResponseFormNull) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_a2,
                        SAMLBindings_3_5_4_b1,
                        message = "The form containing the SAMLResponse from control could not be" +
                                "found." +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
            if (isRelayStateGiven && isRelayStateFormNull) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_c,
                        message = "The RelayState form control could not be found." +
                                "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
            if (samlResponse == null) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_a2,
                        SAMLBindings_3_5_4_b1,
                        message = "The SAMLResponse within the SAMLResponse form control could" +
                                "not be found.\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
            if (isRelayStateGiven && relayState == null) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_3_b,
                        SAMLBindings_3_5_4_c,
                        message = "The RelayState within the RelayState form control could not " +
                                "be found.\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
        }
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the post binding rules
     * in the binding spec
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

        assertNotNull(decodedMessage)
        decodedMessage.debugPrettyPrintXml("Decoded SAML Response")
        response.decodedSamlResponse = decodedMessage
    }

    /**
     * Verifies the encoding of the samlResponse by decoding it according to the post binding rules
     * in the binding spec (Negative path)
     * 3.5.4 Message Encoding
     */
    private fun decodeAndVerifyErrorResponse() {
        val samlResponse = response.samlResponse

        val decodedMessage: String
        try {
            decodedMessage = Decoder.decodePostMessage(samlResponse)
        } catch (exception: Decoder.DecoderException) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a1,
                    message = "The SAML response could not be base64 decoded." +
                            "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                    cause = exception)
        }

        assertNotNull(decodedMessage)
        decodedMessage.debugPrettyPrintXml("Decoded SAML Response")
        response.decodedSamlResponse = decodedMessage
    }

    /**
     * Checks POST-specific rules from SSO profile spec
     * 4.1.4.5 POST-Specific Processing Rules
     */
    private fun verifyPostSSO() {
        if (response.responseDom.children(SIGNATURE).isEmpty()
                || response.responseDom.children("Assertion").any {
                    it.children(SIGNATURE).isEmpty()
                })
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_5,
                    message = "No digital signature found on the Response or Assertions.",
                    node = response.responseDom)
    }

    /**
     * Verifies the relay state according to the post binding rules in the binding spec
     * 3.5.3 RelayState
     */
    private fun verifyPostRelayState() {
        val relayState = response.relayState
        val isRelayStateGiven = response.isRelayStateGiven

        if (relayState.toByteArray().size > MAX_RELAY_STATE_LEN)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_5_3_a,
                    property = RELAY_STATE,
                    actual = relayState)

        if (isRelayStateGiven) {
            if (relayState != EXAMPLE_RELAY_STATE) {
                throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_5_3_b,
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
        val destination = response.responseDom.attributeNode("Destination")?.nodeValue
        val signatures = response.responseDom.recursiveChildren("Signature")

        if (signatures.isNotEmpty() && destination != acsUrl[HTTP_POST]) {
            throw SAMLComplianceException.createWithPropertyMessage(SAMLBindings_3_5_5_2_a,
                    property = "Destination",
                    actual = destination,
                    expected = acsUrl[HTTP_POST],
                    node = response.responseDom)
        }
    }

    /**
     * Verifies the form carrying the SAMLRequest was properly formatted according to the post
     * binding rules in the binding spec
     * 3.5.4 Message Encoding
     */
    // TODO refactor this method and response objects so we can show values in the errors
    private fun verifyPostForm() {
        with(response) {
            if (!isFormActionCorrect) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_d1,
                        message = """The form "action" is incorrect.""")
            }
            if (!isFormMethodCorrect) {
                throw SAMLComplianceException.create(
                        SAMLBindings_3_5_4_d2,
                        message = """The form "method" is incorrect.""")
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
            if (isRelayStateGiven) {
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
}
