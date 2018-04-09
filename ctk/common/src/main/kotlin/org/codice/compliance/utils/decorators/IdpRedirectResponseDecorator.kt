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
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIG_ALG
import org.codice.compliance.saml.plugin.IdpRedirectResponse
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.binding.RedirectBindingVerifier
import org.w3c.dom.Node

/**
 * This class can only be instantiated by using extension methods in IdpResponseDecorator.kt
 */
class IdpRedirectResponseDecorator
internal constructor(response: IdpRedirectResponse) : IdpRedirectResponse(response),
        IdpResponseDecorator {

    private val paramMap: Map<String, String> by lazy {
        parameters.split("&")
                .map { s -> s.split("=") }
                .associate { s -> s[0] to s[1] }
    }

    init {
        samlResponse = paramMap[SAML_RESPONSE]
        relayState = paramMap[RELAY_STATE]
    }

    val samlEncoding: String? by lazy {
        paramMap["SAMLEncoding"]
    }
    val sigAlg: String? by lazy {
        paramMap[SIG_ALG]
    }
    val signature: String? by lazy {
        paramMap[SIGNATURE]
    }

    override var isRelayStateGiven: Boolean = false
    override lateinit var decodedSamlResponse: String
    override val responseDom: Node by lazy {
        checkNotNull(decodedSamlResponse)
        buildDom(decodedSamlResponse)
    }

    val isUrlNull: Boolean by lazy {
        url == null
    }
    val isPathNull: Boolean by lazy {
        path == null
    }
    val isParametersNull: Boolean by lazy {
        parameters == null
    }

    override fun bindingVerifier(): BindingVerifier {
        return RedirectBindingVerifier(this)
    }
}
