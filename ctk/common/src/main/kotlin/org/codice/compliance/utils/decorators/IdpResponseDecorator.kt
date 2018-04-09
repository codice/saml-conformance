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

import org.codice.compliance.Common
import org.codice.compliance.saml.plugin.IdpPostResponse
import org.codice.compliance.saml.plugin.IdpRedirectResponse
import org.codice.compliance.verification.binding.BindingVerifier
import org.w3c.dom.Node

interface IdpResponseDecorator {
    var isRelayStateGiven: Boolean
    var decodedSamlResponse: String
    val responseDom: Node

    fun bindingVerifier(): BindingVerifier
}

fun IdpRedirectResponse.decorate(): IdpRedirectResponseDecorator {
    return IdpRedirectResponseDecorator(this)
}

fun IdpPostResponse.decorate(): IdpPostResponseDecorator {
    return IdpPostResponseDecorator(this)
}

internal fun buildDom(inputXml: String): Node {
    return Common.buildDom(inputXml)
}
