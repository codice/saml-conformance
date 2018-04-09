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
package org.codice.compliance.utils.decorators

import org.apache.cxf.rs.security.saml.sso.SSOConstants.RELAY_STATE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.saml.plugin.IdpPostResponse
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.binding.PostBindingVerifier
import org.codice.security.saml.SamlProtocol
import com.jayway.restassured.path.xml.element.Node as raNode
import org.w3c.dom.Node as w3Node

@Suppress("StringLiteralDuplication")
/**
 * This class  can only be instantiated by using extension methods in IdpResponseDecorator.kt
 */
class IdpPostResponseDecorator
internal constructor(response: IdpPostResponse) : IdpPostResponse(response), IdpResponseDecorator {
    companion object {
        private const val HIDDEN = "hidden"
        private const val TYPE = "type"
        private const val ACTION = "action"
        private const val METHOD = "method"
        private const val POST = "POST"
    }

    init {
        responseBodyString?.debugPrettyPrintXml("HTTP Response Body")
    }

    override var isRelayStateGiven: Boolean = false
    override lateinit var decodedSamlResponse: String

    override val responseDom: w3Node by lazy {
        checkNotNull(decodedSamlResponse)
        buildDom(decodedSamlResponse)
    }

    val isResponseFormNull: Boolean by lazy {
        responseForm == null
    }
    val isSamlResponseFormNull: Boolean by lazy {
        samlResponseFormControl == null
    }
    val isRelayStateFormNull: Boolean by lazy {
        relayStateFormControl == null
    }

    val isSamlResponseNameCorrect: Boolean by lazy {
        checkNodeAttribute(samlResponseFormControl, NAME, SAML_RESPONSE)
    }

    /*
     * Bindings 3.5.4 "The action attribute of the form MUST be the recipient's HTTP endpoint for
     * the protocol or profile using this binding to which the SAML message is to be delivered.
     * The method attribute MUST be "POST"."
     */
    val isFormActionCorrect: Boolean by lazy {
        checkNodeAttribute(responseForm,
                ACTION,
                checkNotNull(acsUrl[SamlProtocol.Binding.HTTP_POST]))
    }

    val isFormMethodCorrect: Boolean by lazy {
        checkNodeAttribute(responseForm, METHOD, POST)
    }

    /*
     * Bindings 3.5.4 "A SAML protocol message is form-encoded by... placing the result **in** a
     * **hidden** form control within a form as defined by [HTML401] Section 17"
     *
     * The two key words here are "in" and "hidden"
     *
     * Assuming "in" in the above quote means in either the value attribute or in the value
     * itself.
     *
     * And "hidden" means both the SAMLResponse and RelayState MUST be placed in "hidden" form
     * controls
     */
    val isSamlResponseHidden: Boolean by lazy {
        checkNodeAttributeIgnoreCase(samlResponseFormControl, TYPE, HIDDEN)
    }
    val isRelayStateNameCorrect: Boolean by lazy {
        require(isRelayStateGiven)
        checkNodeAttribute(relayStateFormControl, NAME, RELAY_STATE)
    }
    val isRelayStateHidden: Boolean by lazy {
        require(isRelayStateGiven)
        checkNodeAttributeIgnoreCase(relayStateFormControl, TYPE, HIDDEN)
    }

    private fun checkNodeAttribute(node: raNode,
                                   attributeName: String,
                                   expectedValue: String): Boolean {
        return expectedValue == node.getAttribute(attributeName)
    }

    private fun checkNodeAttributeIgnoreCase(node: raNode,
                                             attributeName: String,
                                             expectedValue: String): Boolean {
        return expectedValue.equals(node.getAttribute(attributeName), true)
    }

    override fun bindingVerifier(): BindingVerifier {
        return PostBindingVerifier(this)
    }
}
