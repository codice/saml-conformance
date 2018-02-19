package org.codice.compliance.bindings

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.children
import org.w3c.dom.Node

/**
 * Verify the response for a post binding
 */
fun verifyPost(response: Node) {
    verifySsoPost(response)
}

/**
 * Checks POST-specific rules from SSO profile spec
 *
 * @param response - Response node
 */
fun verifySsoPost(response: Node) {
    if (response.children("Signature").isEmpty()
            || response.children("Assertion").any { it.children("Signature").isEmpty() })
        throw SAMLComplianceException.create("10") //If the HTTP POST binding is used to deliver the <Response>, [E26]each assertion MUST be protected by a digital signature. This can be accomplished by signing each individual <Assertion> element or by signing the <Response> element.
}