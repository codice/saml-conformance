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
        throw SAMLComplianceException.create("8")

    val issuer = issuers[0]
    if (issuer.textContent != (idpParsedMetadata?.parent as EntityDescriptorImpl).entityID)
        throw SAMLComplianceException.create("9")

    if (issuer.attributes.getNamedItem("Format") != null && !issuer.attributes.getNamedItem("Format").equals("urn:oasis:names:tc:SAML:2.0:nameid-format:entity"))
        throw SAMLComplianceException.create("10")
}