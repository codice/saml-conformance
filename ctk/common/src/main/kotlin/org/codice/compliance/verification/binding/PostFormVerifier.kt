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
import org.apache.cxf.rs.security.saml.sso.SSOConstants.RELAY_STATE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
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
import org.codice.compliance.utils.ACTION
import org.codice.compliance.utils.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.MAX_RELAY_STATE_LEN
import org.codice.compliance.utils.NAME
import org.codice.compliance.utils.TestCommon.Companion.logoutRequestRelayState
import org.codice.compliance.utils.extractSamlMessageForm
import org.codice.compliance.utils.extractValue
import org.codice.compliance.utils.hasNoAttributeWithNameAndValue
import org.codice.compliance.utils.isNotHidden

@Suppress("StringLiteralDuplication" /* Duplicated phrases in exception messages. */)
class PostFormVerifier(private val httpResponse: Response, private val isRelayStateGiven: Boolean,
    private val isSamlRequest: Boolean) {
    companion object {
        private const val METHOD = "method"
        private const val POST = "POST"
    }

    private val type = if (isSamlRequest) SAML_REQUEST else SAML_RESPONSE
    private val isNamedRelayState = { formControl: Node ->
        RELAY_STATE.equals(formControl.attributes()[NAME], ignoreCase = true)
    }
    private val isNamedCorrectly = { formControl: Node ->
        type.equals(formControl.attributes()[NAME], ignoreCase = true)
    }

    private val samlMessageForm: Node? = httpResponse.extractSamlMessageForm()
    private val samlMessageFormControl: Node?
    private val samlMessage: String?
    private val relayStateFormControl: Node?
    private val relayState: String?

    init {
        samlMessageFormControl =
                samlMessageForm
                        ?.children()
                        ?.list()
                        ?.firstOrNull(isNamedCorrectly)
        samlMessage = samlMessageFormControl?.extractValue()
        relayStateFormControl =
                samlMessageForm
                        ?.children()
                        ?.list()
                        ?.firstOrNull(isNamedRelayState)
        relayState = relayStateFormControl?.extractValue()
    }

    /** Verify the response for a post binding */
    fun verifyAndParse(): String {
        verifyNoNulls()
        if (samlMessage == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    SAMLBindings_3_5_4_b,
                    message = "The $type within the $type form control could not be found.")
        }
        verifyPostForm()
        if (isRelayStateGiven || relayState != null) {
            verifyPostRelayState()
        }
        return samlMessage
    }

    /** Verify an error response (Negative path) */
    fun verifyAndParseError(): String {
        verifyNoNulls()
        verifyPostForm()
        if (samlMessage == null) {
            throw SAMLComplianceException.create(
                    SAMLBindings_3_5_4_a,
                    SAMLBindings_3_5_4_b,
                    message = "The SAMLResponse within the SAMLResponse form control could" +
                            "not be found.")
        }
        return samlMessage
    }

    /**
     * Verifies the presence of post forms and values according to the post binding rules in
     * the binding spec
     * 3.5.4 Message Encoding
     */
    private fun verifyNoNulls() {
        if (samlMessageForm == null) {
            Log.debugWithSupplier {
                httpResponse.then().extract().body().asString().prettyPrintXml()
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
     * Verifies the form carrying the SAMLRequest was properly formatted according to the post
     * binding rules in the binding spec
     * 3.5.4 Message Encoding
     */
// TODO refactor this method and response objects so we can show values in the errors
    @Suppress("ComplexMethod", "NestedBlockDepth")
    private fun verifyPostForm() {
        samlMessageForm?.let {
            if (it.getAttribute(ACTION).isNullOrEmpty()) {
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
        samlMessageFormControl?.let {
            if (it.hasNoAttributeWithNameAndValue(NAME, type)) {
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

        if (isSamlRequest) {
            logoutRequestRelayState = relayState
        }
    }
}
