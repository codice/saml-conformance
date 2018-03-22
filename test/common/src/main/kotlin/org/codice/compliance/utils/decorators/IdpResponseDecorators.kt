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

import org.codice.compliance.saml.plugin.IdpPostResponse
import org.codice.compliance.saml.plugin.IdpRedirectResponse
import org.codice.compliance.verification.binding.PostBindingVerifier
import org.codice.compliance.verification.binding.RedirectBindingVerifier
import org.w3c.dom.Node
import javax.xml.parsers.DocumentBuilderFactory

fun IdpRedirectResponse.decorate(): IdpRedirectResponseDecorator {
    return IdpRedirectResponseDecorator(this)
}

fun IdpPostResponse.decorate(): IdpPostResponseDecorator {
    return IdpPostResponseDecorator(this)
}

fun IdpRedirectResponseDecorator.bindingVerifier(): RedirectBindingVerifier {
    return RedirectBindingVerifier(this)
}

fun IdpPostResponseDecorator.bindingVerifier(): PostBindingVerifier {
    return PostBindingVerifier(this)
}

internal fun buildDom(decodedSamlResponse: String): Node {
    return DocumentBuilderFactory.newInstance().apply {
        isNamespaceAware = true
    }.newDocumentBuilder()
            .parse(decodedSamlResponse.byteInputStream())
            .documentElement
}
