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

import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorImpl
import org.w3c.dom.Node

fun assertAllLoginResponse(responseElement: Node) {
    val status = responseElement.children("Status")
    val assertion = responseElement.children("Assertion")

    checkIssuer(responseElement)
    checkAssertions(assertion)
}

/**
 * Checks the issuer element for SAML spec compliance.
 *
 * @param node - Node containing the issuer to verify.
 * If node is an assertion, checks the issuer directly otherwise,
 * if node is a response, checks if the message is signed or if an enclosed assertion is encrypted first
 */
fun checkIssuer(node: Node) {
    if(node.localName == "Assertion" ||
            // If the message is signed or if an enclosed assertion is encrypted
            (node.localName == "Response" &&
                    (node.children("Signature").isNotEmpty() ||
                            node.children("Assertion").filter { it.children("Signature").isNotEmpty()}.count() > 0))) {

        val issuers = node.children("Issuer")



        if (issuers.isEmpty() || issuers.size > 1)
            throw SAMLComplianceException("If the <Response> message is signed or if an enclosed assertion is encrypted, then the <Issuer> element MUST be present.")

        val issuer = issuers[0]
        if (issuer.textContent != (IDP_METADATA?.parent as EntityDescriptorImpl).entityID)
            throw SAMLComplianceException("If present [the Issuer] MUST contain the unique identifier of the issuing identity provider.")

        if (issuer.attributes.getNamedItem("Format") != null && !issuer.attributes.getNamedItem("Format").equals("urn:oasis:names:tc:SAML:2.0:nameid-format:entity"))
            throw SAMLComplianceException("The Format attribute MUST be omitted or have a value of urn:oasis:names:tc:SAML:2.0:nameid-format:entity.")
    }
}