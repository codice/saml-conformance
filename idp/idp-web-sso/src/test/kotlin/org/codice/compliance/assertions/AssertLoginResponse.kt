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
package org.codice.compliance.assertions

import org.codice.security.saml.SamlProtocol
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorImpl
import org.w3c.dom.Node

fun assertAllLoginResponse(responseElement: Node, binding : String) {
    val status = responseElement.children("Status")
    val assertion = responseElement.children("Assertion")

    checkIssuer(responseElement)
    checkAssertions(assertion)

    if (binding == SamlProtocol.POST_BINDING)
        checkPostSpec(responseElement)

//    if (binding == SamlProtocol.REDIRECT_BINDING)
//        checkRedirectSpec(responseElement)
}

/**
 * Checks the issuer element for SAML spec compliance.
 *
 * @param node - Node containing the issuer to verify.
 * If node is an assertion, checks the issuer directly otherwise,
 * if node is a response, checks if the message is signed or if an enclosed assertion is encrypted first
 */
fun checkIssuer(node: Node) {
    if (node.localName == "Assertion" ||
            // If the message is signed or if an enclosed assertion is encrypted
            (node.localName == "Response" &&
                    (node.children("Signature").isNotEmpty() ||
                            node.children("Assertion").filter { it.children("Signature").isNotEmpty() }.count() > 0))) {

        val issuers = node.children("Issuer")

        if (issuers.isEmpty() || issuers.size > 1)
            throw SAMLComplianceException.create("8")

        val issuer = issuers[0]
        if (issuer.textContent != (idpParsedMetadata?.parent as EntityDescriptorImpl).entityID)
            throw SAMLComplianceException.create("9")

        if (issuer.attributes.getNamedItem("Format") != null && !issuer.attributes.getNamedItem("Format").equals("urn:oasis:names:tc:SAML:2.0:nameid-format:entity"))
            throw SAMLComplianceException.create("10")
    }
}

/**
 * Checks POST-specific rules
 *
 * @param response - Response node
 */
fun checkPostSpec(response: Node) {
    if (response.children("Signature").isEmpty()
            || response.children("Assertion").any { it.children("Signature").isEmpty() })
        throw SAMLComplianceException.create("10") //If the HTTP POST binding is used to deliver the <Response>, [E26]each assertion MUST be protected by a digital signature. This can be accomplished by signing each individual <Assertion> element or by signing the <Response> element.
}

/**
 * Checks Redirect-specific rules
 *
 * @param response - Response node
 */
fun checkRedirectSpec(response: Node) {
    TODO("not implemented") //To change body of created functions use File | Settings | File Templates.
}