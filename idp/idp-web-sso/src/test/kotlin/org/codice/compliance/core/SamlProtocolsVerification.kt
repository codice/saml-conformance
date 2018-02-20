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

import com.google.common.collect.ImmutableSet
import org.codice.compliance.ID
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.w3c.dom.Node

private val topLevelStatusCodes = ImmutableSet.of("urn:oasis:names:tc:SAML:2.0:status:Success",
        "urn:oasis:names:tc:SAML:2.0:status:Requester",
        "urn:oasis:names:tc:SAML:2.0:status:Responder",
        "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch")

/**
 * Verify protocols against the Core Spec document
 * 3 SAML Protocols
 */
fun verifyProtocols(response: Node) {
    verifyStatuses(response)
    verifyQueries(response)
    verifyAuthenticationRequestProtocol(response)
}

/**
 * Verify the Statuses
 * 3.2.2 Complex Type StatusResponseType
 * 3.2.2.1 Element <Status>
 * 3.2.2.2 Element <StatusCode>
 */
fun verifyStatuses(response: Node) {
    // StatusResponseType
    if (response.attributes.getNamedItem("ID") == null)
        throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.2.2", "ID", "Response")

    // Assuming response is generated in response to a request
    val inResponseTo = response.attributes.getNamedItem("InResponseTo")
    if (inResponseTo == null || inResponseTo.textContent != ID)
        throw SAMLComplianceException.create("SAMLCore.3.2.2_a")

    if (response.attributes.getNamedItem("Version").textContent != "2.0")
        throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.2.2", "Version", "Response")

    if (response.attributes.getNamedItem("IssueInstant") == null)
        throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.2.2", "IssueInstant", "Response")

    if (response.children("Status").isEmpty())
        throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.2.2", "Status", "Response")

    // Status
    val statuses = response.children("Status")
    statuses.forEach {
        val statusCodes = it.children("StatusCode")
        if (statusCodes.isEmpty())
            throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.2.2.1", "StatusCode", "Status")

        // StatusCode
        val topStatusCode = statusCodes[0]
        statusCodes.forEach {
            if (it.attributes.getNamedItem("Value") == null)
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.2.2.2", "Value", "StatusCode")

            if (it == topStatusCode && !topLevelStatusCodes.contains(it.attributes.getNamedItem("Value").textContent))
                throw SAMLComplianceException.create("SAMLCore.3.2.2.2_a", "SAMLCore.3.2.2.2_b")
        }
    }
}

/**
 * Verify the Queries
 * 3.3.2.2 Element <AuthnQuery>
 * 3.3.2.2.1 Element <RequestedAuthnContext>
 * 3.3.2.3 Element <AttributeQuery>
 * 3.3.2.4 Element <AuthzDecisionQuery>
 */
fun verifyQueries(response: Node) {
    // AuthnQuery
    val authnQueries = response.allChildren("AuthnQuery")
    authnQueries.forEach {
        val querySessionIndex = it.attributes.getNamedItem("SessionIndex")
        if (querySessionIndex != null
                && response.children("Assertion")
                .filter { it.children("AuthnStatement").isNotEmpty() }
                .none { it.attributes.getNamedItem("SessionIndex") == querySessionIndex })
            throw SAMLComplianceException.create("SAMLCore.3.3.2.2_a")

        val requestedAuthnContexts = it.children("RequestedAuthnContext")
        if (requestedAuthnContexts.isNotEmpty()) {
            if (response.children("Assertion")
                    .filter { it.children("AuthnStatement").isNotEmpty() }
                    // todo - that satisfies the element in the query (see Section 3.3.2.2.1).
                    .none { it.children("AuthnContext").isNotEmpty() })
                throw SAMLComplianceException.create("SAMLCore.3.3.2.2_b")

            //RequestedAuthnContext
            requestedAuthnContexts.forEach {
                if (it.children("AuthnContextClassRef").isEmpty()
                        && it.children("AuthnContextDeclRef").isEmpty())
                    throw SAMLComplianceException.createWithReqMessage("3.3.2.2.1", "AuthnContextClassRef or AuthnContextDeclRef", "RequestedAuthnContext")
            }
        }
    }

    // AttributeQuery
    val attributeQueries = response.allChildren("AuthnQuery")
    attributeQueries.forEach {
        val uniqueAttributeQuery = mutableMapOf<String, String>()
        attributeQueries.forEach {
            val name = it.attributes.getNamedItem("Name").textContent
            if (uniqueAttributeQuery.containsKey(name)
                    && uniqueAttributeQuery.getValue(name) == it.attributes.getNamedItem("NameFormat").textContent) {
                throw SAMLComplianceException.create("SAMLCore.3.3.2.3_a")
            } else {
                uniqueAttributeQuery.put(it.attributes.getNamedItem("Name").textContent,
                        it.attributes.getNamedItem("NameFormat").textContent)
            }
        }
    }

    // AuthzDecisionQuery
    val authzDecisionQueries = response.allChildren("AuthzDecisionQuery")
    authzDecisionQueries.forEach {
        if (it.attributes.getNamedItem("Resource") == null)
            throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.3.2.4", "Resource", "AuthzDecisionQuery")

        if (it.children("Action").isEmpty())
            throw SAMLComplianceException.createWithReqMessage("SAMLCore3.3.2.4", "Action", "AuthzDecisionQuery")
    }
}

/**
 * Verify the Authentication Request Protocol
 * 3.4.1.1 Element <NameIDPolicy>
 * 3.4.1.3 Element <IDPList>
 * 3.4.1.3.1 Element <IDPEntry>
 */
fun verifyAuthenticationRequestProtocol(response: Node) {
    // NameIDPolicy

    // todo - Verify correctness of check and uncomment below block
    // Testing -> "The special Format value urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted indicates that the resulting
    // assertion(s) MUST contain <EncryptedID> elements instead of plaintext.

    /*
    val nameIdPolicy = response.allChildren("NameIDPolicy")
    val assertions = response.allChildren("NameIDPolicy")
    nameIdPolicy.forEach {
        if (it.attributes.getNamedItem("Format").textContent == "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted") {
            assertions.any { it.children("EncryptedID").isEmpty() }
            throw SAMLComplianceException.create("SAMLCore.3.4.1.1_a")
        }
    }
    */

    // todo - [E15]When a Format defined in Section 8.3 other than urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified or
    // urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted is used, then if the identity provider returns any assertions:
    // - the Format value of the <NameID> within the <Subject> of any <Assertion> MUST be identical to the Format value supplied
    // in the <NameIDPolicy>, and
    // - if SPNameQualifier is not omitted in <NameIDPolicy>, the SPNameQualifier value of the <NameID> within the <Subject> of
    // any <Assertion> MUST be identical to the SPNameQualifier value supplied in the <NameIDPolicy>.

    // IDPList
    val idpLists = response.allChildren("IDPList")
    idpLists.forEach {
        val idpEntries = it.children("IDPEntry")
        if(idpEntries.isEmpty())
            throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.4.1.3", "IDPEntry", "IDPList")

        //IDPEntry
        idpEntries.forEach {
            if(it.attributes.getNamedItem("ProviderID") == null)
                throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.4.1.3.1", "ProviderID", "IDPEntry")
        }
    }
}