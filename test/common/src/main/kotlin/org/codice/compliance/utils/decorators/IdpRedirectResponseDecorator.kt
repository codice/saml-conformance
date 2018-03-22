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
import org.w3c.dom.Node

class IdpRedirectResponseDecorator : IdpRedirectResponse {

    // can only instantiate by using extension methods in IdpResponseDecorators.kt
    internal constructor(response: IdpRedirectResponse) : super(response) {
        parameters.split("&")
                .forEach({
                    val (key, value) = it.split("=")
                    paramMap[key] = value
                })

        samlResponse = paramMap[SAML_RESPONSE]
        relayState = paramMap[RELAY_STATE]
    }

    private val paramMap: MutableMap<String, String> = HashMap()

    val samlEncoding: String? by lazy {
        paramMap["SAMLEncoding"]
    }
    val sigAlg: String? by lazy {
        paramMap[SIG_ALG]
    }
    val signature: String? by lazy {
        paramMap[SIGNATURE]
    }

    val extraUrlParameters: Boolean by lazy {
        val tempMap = HashMap(paramMap)
        tempMap.remove(SAML_RESPONSE)
        tempMap.remove(RELAY_STATE)
        tempMap.remove("SAMLEncoding")
        tempMap.remove(SIG_ALG)
        tempMap.remove(SIGNATURE)

        tempMap.size > 0
    }

    var isRelayStateGiven: Boolean = false
    lateinit var decodedSamlResponse: String
    val responseDom: Node by lazy {
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
}
