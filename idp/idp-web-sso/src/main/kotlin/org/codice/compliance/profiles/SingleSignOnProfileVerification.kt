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
package org.codice.compliance.profiles

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.children
import org.codice.compliance.idpParsedMetadata
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorImpl
import org.w3c.dom.Node

/**
 * Verify response against the Core Spec document
 */
fun verifySsoProfile(response: Node) {
    if (response.localName == "Response" &&
            (response.children("Signature").isNotEmpty() ||
                    response.children("Assertion").filter { it.children("Signature").isNotEmpty() }.count() > 0))
        verifyIssuer(response)
    verifySsoAssertions(response)
}

/**
 * Checks the issuer element against the SSO profile spec
 *
 * @param node - Node containing the issuer to verify.
 */
fun verifyIssuer(node: Node) {
    val issuers = node.children("Issuer")

    if (issuers.isEmpty() || issuers.size > 1)
        throw SAMLComplianceException.create("SAMLProfiles.4.1.4.2a")

    val issuer = issuers[0]
    if (issuer.textContent != (idpParsedMetadata?.parent as EntityDescriptorImpl).entityID)
        throw SAMLComplianceException.create("SAMLProfiles.4.1.4.2b")

    if (issuer.attributes.getNamedItem("Format") != null && !issuer.attributes.getNamedItem("Format").equals("urn:oasis:names:tc:SAML:2.0:nameid-format:entity"))
        throw SAMLComplianceException.create("SAMLProfiles.4.1.4.2c")
}