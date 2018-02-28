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
package org.codice.compliance.core

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.w3c.dom.Node

/**
 * Verify protocols against the Core Spec document
 * 3.2.1 Complex Type StatusResponseType
 */
fun verifyCoreRequestProtocol(request: Node) {
    verifyRequestAbstractType(request)
    verifyAuthnQueries(request)
    verifyAttributeQueries(request)
    verifyAuthzDecisionQueries(request)
    verifyAuthenticationRequestProtocol(request)
}

/**
 * Verify the Request Abstract Types
 * 3.2.1 Complex Type RequestAbstractType
 * All SAML requests are of types that are derived from the abstract RequestAbstractType complex type.
 */
fun verifyRequestAbstractType(request: Node) {
    if (request.attributes.getNamedItem("ID") == null)
        throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.2.1", "ID", "Request")
    verifyIdValues(request.attributes.getNamedItem("ID"), "SAMLCore.3.2.1_a")

    if (request.attributes.getNamedItem("Version") == null)
        throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.2.1", "Version", "Request")

    if (request.attributes.getNamedItem("Version").textContent != "2.0")
        throw SAMLComplianceException.create("SAMLCore.3.2.1_b")

    if (request.attributes.getNamedItem("IssueInstant") == null)
        throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.2.1", "IssueInstant", "Request")
    verifyTimeValues(request.attributes.getNamedItem("IssueInstant"), "SAMLCore.3.2.1_c")
}

/**
 * Verify the Authn Queries
 * 3.3.2.2 Element <AuthnQuery>
 * The <AuthnQuery> message element is used to make the query “What assertions containing authentication statements are available for this subject?”
 */
fun verifyAuthnQueries(request: Node) {
    // AuthnQuery
    request.allChildren("AuthnQuery").forEach {
        val querySessionIndex = it.attributes.getNamedItem("SessionIndex")?.textContent
        if (querySessionIndex != null
                && request.children("Assertion")
                .filter { it.children("AuthnStatement").isNotEmpty() }
                .none { it.attributes.getNamedItem("SessionIndex")?.textContent == querySessionIndex })
            throw SAMLComplianceException.create("SAMLCore.3.3.2.2_a")

        //RequestedAuthnContext
        it.children("RequestedAuthnContext").forEach { verifyRequestedAuthnContext(it) }

        // todo - verify correctness
        if (it.children("RequestedAuthnContext").isNotEmpty()
                && request.children("Assertion")
                .filter { it.children("AuthnStatement").isNotEmpty() }
                .flatMap { it.children("AuthnStatement") }
                .filter { it.children("AuthnContext").isNotEmpty() }
                .filter { verifyRequestedAuthnContext(it) }
                .count() < 1)
            throw SAMLComplianceException.create("SAMLCore.3.3.2.2_b")
    }
}

/**
 * Verifies the Requested Authn Contexts against the core spec
 *
 * 3.3.2.2.1 Element <RequestedAuthnContext>
 * The <RequestedAuthnContext> element specifies the authentication context requirements of authentication statements returned in response to a request or query.
 *
 * @throws SAMLComplianceException - if the check fails
 * @return true - if the check succeeds
 */
private fun verifyRequestedAuthnContext(requestedAuthnContext: Node): Boolean {
    if (requestedAuthnContext.children("AuthnContextClassRef").isEmpty()
            && requestedAuthnContext.children("AuthnContextDeclRef").isEmpty())
        throw SAMLComplianceException.createWithReqMessage("3.3.2.2.1", "AuthnContextClassRef or AuthnContextDeclRef", "RequestedAuthnContext")
    return true
}

/**
 * Verify the Attribute Queries
 *
 * 3.3.2.3 Element <AttributeQuery>
 * The <AttributeQuery> element is used to make the query “Return the requested attributes for this subject.”
 */
fun verifyAttributeQueries(request: Node) {
    val uniqueAttributeQuery = mutableMapOf<String, String>()
    request.allChildren("AuthnQuery").forEach {
        val name = it.attributes.getNamedItem("Name")
        val nameFormat = it.attributes.getNamedItem("NameFormat")
        if (name != null && nameFormat != null) {
            if (uniqueAttributeQuery.containsKey(name.textContent)
                    && uniqueAttributeQuery[name.textContent] == nameFormat.textContent)
                throw SAMLComplianceException.create("SAMLCore.3.3.2.3_a")
            else uniqueAttributeQuery.put(name.textContent, nameFormat.textContent)
        }
    }
}

/**
 * Verify the Authz Decision Queries
 *
 * 3.3.2.4 Element <AuthzDecisionQuery>
 * The <AuthzDecisionQuery> element is used to make the query “Should these actions on this resource be allowed for this subject, given this evidence?”
 */
fun verifyAuthzDecisionQueries(request: Node) {
    request.allChildren("AuthzDecisionQuery").forEach {
        if (it.attributes.getNamedItem("Resource") == null)
            throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.3.2.4", "Resource", "AuthzDecisionQuery")

        if (it.children("Action").isEmpty())
            throw SAMLComplianceException.createWithReqMessage("SAMLCore3.3.2.4", "Action", "AuthzDecisionQuery")
    }
}

/**
 * Verify the Authentication Request Protocol
 * 3.4.1.3 Element <IDPList>
 * 3.4.1.3.1 Element <IDPEntry>
 */
fun verifyAuthenticationRequestProtocol(node: Node) {
    // IDPList
    val idpLists = node.allChildren("IDPList")
    idpLists.forEach {
        val idpEntries = it.children("IDPEntry")
        if (idpEntries.isEmpty())
            throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.4.1.3", "IDPEntry", "IDPList")

        //IDPEntry
        idpEntries.forEach {
            if (it.attributes.getNamedItem("ProviderID") == null)
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.4.1.3.1", "ProviderID", "IDPEntry")
        }
    }
}