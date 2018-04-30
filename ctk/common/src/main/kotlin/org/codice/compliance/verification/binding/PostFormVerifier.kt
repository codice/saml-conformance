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

import com.jayway.restassured.path.xml.element.Node
import com.jayway.restassured.response.Response
import de.jupf.staticlog.Log
import org.apache.commons.lang3.StringUtils.isNotEmpty
import org.apache.cxf.rs.security.saml.sso.SSOConstants.RELAY_STATE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.codice.compliance.SAMLBindings_3_5_3_a
import org.codice.compliance.SAMLBindings_3_5_3_b
import org.codice.compliance.SAMLBindings_3_5_4_a
import org.codice.compliance.SAMLBindings_3_5_4_b
import org.codice.compliance.SAMLBindings_3_5_4_c
import org.codice.compliance.SAMLBindings_3_5_4_d
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.debugWithSupplier
import org.codice.compliance.prettyPrintXml
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.IDP_ERROR_RESPONSE_REMINDER_MESSAGE
import org.codice.compliance.utils.TestCommon.Companion.MAX_RELAY_STATE_LEN
import org.codice.compliance.utils.TestCommon.Companion.NAME
import org.codice.compliance.utils.TestCommon.Companion.VALUE
import org.codice.compliance.utils.extractSamlResponseForm
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST

/* Small pieces of exception messages are being picked up on. */
@Suppress("StringLiteralDuplication")
class PostFormVerifier(val response: Response, val isRelayStateGiven: Boolean) {
    companion object {
        private const val HIDDEN = "hidden"
        private const val TYPE = "type"
        private const val ACTION = "action"
        private const val METHOD = "method"
        private const val POST = "POST"
        private val isNamedRelayState = { formControl: Node ->
            RELAY_STATE.equals(formControl.attributes().get(TestCommon.NAME), ignoreCase = true)
        }
        private val isNamedSamlResponse = { formControl: Node ->
            SAML_RESPONSE.equals(formControl.attributes().get(TestCommon.NAME), ignoreCase = true)
        }
    }

    private val responseForm: Node?
    private val samlResponseFormControl: Node?
    private val samlResponse: String?
    private val relayStateFormControl: Node?
    private val relayState: String?

    init {
        responseForm = response.extractSamlResponseForm()
        samlResponseFormControl =
                responseForm
                        ?.children()
                        ?.list()
                        ?.firstOrNull(isNamedSamlResponse)
        samlResponse = samlResponseFormControl?.extractValue()
        relayStateFormControl =
                responseForm
                        ?.children()
                        ?.list()
                        ?.firstOrNull(isNamedRelayState)
        relayState = relayStateFormControl?.extractValue()
    }

    /** Verify the response for a post binding */
    fun verifyAndParse(): String {
        verifyNoNulls()
        if (samlResponse == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    SAMLBindings_3_5_4_b,
                    message = "The SAMLResponse within the SAMLResponse form control could " +
                            "not be found.")
        }
        verifyPostForm()
        if (isRelayStateGiven || relayState != null) {
            verifyPostRelayState()
        }
        return samlResponse
    }

    /** Verify an error response (Negative path) */
    fun verifyAndParseError(): String {
        verifyNoNullsError()
        verifyPostFormError()
        if (samlResponse == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    SAMLBindings_3_5_4_b,
                    message = "The SAMLResponse within the SAMLResponse form control could" +
                            "not be found.\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
        }
        return samlResponse
    }

    /**
     * Verifies the presence of post forms and values according to the post binding rules in
     * the binding spec
     * 3.5.4 Message Encoding
     */
    private fun verifyNoNulls() {
        if (responseForm == null) {
            Log.debugWithSupplier {
                response.then().extract().body().asString().prettyPrintXml()
            }
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    SAMLBindings_3_5_4_b,
                    message = "The form containing the SAMLResponse from control could not be" +
                            "found.")
        }
        if (isRelayStateGiven && relayStateFormControl == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_c,
                    message = "The RelayState form control could not be found.")
        }
        if (isRelayStateGiven && relayState == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_3_b,
                    SAMLBindings_3_5_4_c,
                    message = "The RelayState within the RelayState form control could not" +
                            "be found.")
        }
    }

    /**
     * Verifies the presence of post forms and values according to the post binding rules in
     * the binding spec (Negative path)
     * 3.5.4 Message Encoding
     */
    private fun verifyNoNullsError() {
        if (responseForm == null) {
            Log.debugWithSupplier {
                response.then().extract().body().asString().prettyPrintXml()
            }
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    SAMLBindings_3_5_4_b,
                    message = "The form containing the SAMLResponse from control could not be" +
                            "found." +
                            "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
        }
        if (isRelayStateGiven && relayStateFormControl == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_c,
                    message = "The RelayState form control could not be found." +
                            "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
        }
        if (isRelayStateGiven && relayState == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_3_b,
                    SAMLBindings_3_5_4_c,
                    message = "The RelayState within the RelayState form control could not " +
                            "be found.\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
        }
    }

    /**
     * Verifies the form carrying the SAMLRequest was properly formatted according to the post
     * binding rules in the binding spec
     * 3.5.4 Message Encoding
     */
// TODO refactor this method and response objects so we can show values in the errors
    @Suppress("ComplexMethod", "NestedBlockDepth")
    private fun verifyPostForm() {
        with(response) {
            responseForm?.let {
                if (it.hasNoAttributeWithNameAndValue(ACTION,
                                checkNotNull(TestCommon.acsUrl[HTTP_POST]))) {
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_5_4_d,
                            message = """The form "action" is incorrect.""")
                }
                if (it.hasNoAttributeWithNameAndValue(METHOD, POST)) {
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_5_4_d,
                            message = """The form "method" is incorrect.""")
                }
            }
            samlResponseFormControl?.let {
                if (it.hasNoAttributeWithNameAndValue(NAME, SAML_RESPONSE)) {
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_5_4_b,
                            message = "The SAMLResponse form control was incorrectly named.")
                }
                if (it.isNotHidden()) {
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_5_4_a,
                            message = "The SAMLResponse form control was not hidden.")
                }
            }
            if (isRelayStateGiven) {
                relayStateFormControl?.let {
                    if (it.hasNoAttributeWithNameAndValue(NAME, RELAY_STATE)) {
                        throw SAMLComplianceException.create(
                                SAMLBindings_3_5_4_c,
                                message = "The RelayState form control was incorrectly named.")
                    }
                    if (it.isNotHidden()) {
                        throw SAMLComplianceException.create(
                                SAMLBindings_3_5_4_c,
                                message = "The RelayState form control was not hidden.")
                    }
                }
            }
        }
    }

    @Suppress("ComplexMethod", "NestedBlockDepth")
    private fun verifyPostFormError() {
        with(response) {
            responseForm?.let {
                if (it.hasNoAttributeWithNameAndValue(ACTION,
                                checkNotNull(TestCommon.acsUrl[HTTP_POST]))) {
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_5_4_d,
                            message = """The form "action" is incorrect.""" +
                                    "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
                }
                if (it.hasNoAttributeWithNameAndValue(METHOD, POST)) {
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_5_4_d,
                            message = """The form "method" is incorrect.""" +
                                    "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
                }
            }
            samlResponseFormControl?.let {
                if (it.hasNoAttributeWithNameAndValue(NAME, SAML_RESPONSE)) {
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_5_4_b,
                            message = "The SAMLResponse form control was incorrectly named." +
                                    "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
                }
                if (it.isNotHidden()) {
                    throw SAMLComplianceException.create(
                            SAMLBindings_3_5_4_a,
                            message = "The SAMLResponse form control was not hidden." +
                                    "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
                }
            }
            if (isRelayStateGiven) {
                relayStateFormControl?.let {
                    if (isRelayStateGiven && it.hasNoAttributeWithNameAndValue(NAME, RELAY_STATE)) {
                        throw SAMLComplianceException.create(
                                SAMLBindings_3_5_4_c,
                                message = "The RelayState form control was incorrectly named." +
                                        "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
                    }
                    if (it.isNotHidden()) {
                        throw SAMLComplianceException.create(
                                SAMLBindings_3_5_4_c,
                                message = "The RelayState form control was not hidden." +
                                        "\n$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
                    }
                }
            }
        }
    }

    /**
     * Verifies the relay state according to the post binding rules in the binding spec
     * 3.5.3 RelayState
     */
    private fun verifyPostRelayState() {
        if (relayState != null && relayState.toByteArray().size > MAX_RELAY_STATE_LEN)
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

    private fun Node.extractValue(): String? {
        if (isNotEmpty(this.value())) {
            return this.value()
        }

        return if (isNotEmpty(this.attributes()?.get(VALUE))) {
            this.attributes()?.get(VALUE)
        } else null
    }

    private fun Node.isNotHidden(): Boolean {
        return !HIDDEN.equals(this.getAttribute(TYPE), ignoreCase = true)
    }

    private fun Node.hasNoAttributeWithNameAndValue(attributeName: String,
                                                    expectedValue: String): Boolean {
        return expectedValue != this.getAttribute(attributeName)
    }
}
