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
package org.codice.compliance.verification.core

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_2_1_a
import org.codice.compliance.SAMLCore_3_2_1_b
import org.codice.compliance.SAMLCore_3_2_1_c
import org.codice.compliance.SAMLCore_3_3_2_2_a
import org.codice.compliance.SAMLCore_3_3_2_2_b
import org.codice.compliance.SAMLCore_3_3_2_3
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.w3c.dom.Node

@Suppress("StringLiteralDuplication")
class RequestProtocolVerifier(private val request: Node) {
    /**
     * Verify protocols against the Core Spec document
     * 3.2.1 Complex Type StatusResponseType
     */
    fun verifyCoreRequestProtocol() {
        CoreVerifier(request).verify()
        verifyRequestAbstractType()
        verifyAuthnQueries()
        verifyAttributeQueries()
        verifyAuthzDecisionQueries()
        verifyAuthenticationRequestProtocol()
        verifyArtifactResolutionProtocol()
        verifyManageNameIDRequest()
        verifyNameIdMappingRequest()
    }

    /**
     * Verify the Request Abstract Types
     * 3.2.1 Complex Type RequestAbstractType
     * All SAML requests are of types that are derived from the abstract RequestAbstractType
     * complex type.
     */
    private fun verifyRequestAbstractType() {
        if (request.attributes.getNamedItem("ID") == null)
            throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.2.1",
                    "ID",
                    "Request",
                    node = request)
        verifyIdValues(request.attributes.getNamedItem("ID"), SAMLCore_3_2_1_a)

        if (request.attributes.getNamedItem("Version") == null)
            throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.2.1",
                    "Version",
                    "Request",
                    node = request)

        if (request.attributes.getNamedItem("Version").textContent != "2.0")
            throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_1_b,
                    property = "Version",
                    actual = request.attributes.getNamedItem("Version").textContent,
                    expected = "2.0",
                    node = request)

        if (request.attributes.getNamedItem("IssueInstant") == null)
            throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.2.1",
                    "IssueInstant",
                    "Request",
                    node = request)
        verifyTimeValues(request.attributes.getNamedItem("IssueInstant"), SAMLCore_3_2_1_c)
    }

    /**
     * Verify the Authn Queries
     * 3.3.2.2 Element <AuthnQuery>
     * The <AuthnQuery> message element is used to make the query “What assertions containing
     * authentication statements are available for this subject?”
     */
    private fun verifyAuthnQueries() {
        // AuthnQuery
        request.allChildren("AuthnQuery").forEach {
            val querySessionIndex = it.attributes.getNamedItem("SessionIndex")?.textContent
            if (querySessionIndex != null
                    && request.children("Assertion")
                            .flatMap { ast -> ast.children("AuthnStatements") }
                            .map { auth -> auth.attributes.getNamedItem("SessionIndex") }
                            .filterNotNull()
                            .map { sidx -> sidx.textContent }
                            .none { t -> t == querySessionIndex }) {
                throw SAMLComplianceException.create(SAMLCore_3_3_2_2_a,
                        message = "There was no AuthnStatement in the Assertion that had a " +
                                "SessionsIndex of $querySessionIndex.",
                        node = request)
            }

            //RequestedAuthnContext
            it.children("RequestedAuthnContext").forEach { verifyRequestedAuthnContext(it) }

            // todo - verify correctness (brandan - I think this is correct but missing a last step:
            // "<AuthnContext>
            // element that satisfies the element in the query")
            if (it.children("RequestedAuthnContext").isNotEmpty()
                    && request.children("Assertion")
                            .filter { it.children("AuthnStatement").isNotEmpty() }
                            .flatMap { it.children("AuthnStatement") }
                            .filter { it.children("AuthnContext").isNotEmpty() }
                            .filter { verifyRequestedAuthnContext(it) }
                            .count() < 1)
                throw SAMLComplianceException.create(SAMLCore_3_3_2_2_b,
                        message = "No AuthnStatement element found that meets the criteria.",
                        node = request)
        }
    }

    /**
     * Verifies the Requested Authn Contexts against the core spec
     *
     * 3.3.2.2.1 Element <RequestedAuthnContext>
     * The <RequestedAuthnContext> element specifies the authentication context requirements of
     * authentication statements returned in response to a request or query.
     *
     * @throws SAMLComplianceException - if the check fails
     * @return true - if the check succeeds
     */
    private fun verifyRequestedAuthnContext(requestedAuthnContext: Node): Boolean {
        if (requestedAuthnContext.children("AuthnContextClassRef").isEmpty()
                && requestedAuthnContext.children("AuthnContextDeclRef").isEmpty())
            throw SAMLComplianceException.createWithXmlPropertyReqMessage("3.3.2.2.1",
                    "AuthnContextClassRef or AuthnContextDeclRef",
                    "RequestedAuthnContext",
                    node = requestedAuthnContext)
        return true
    }

    /**
     * Verify the Attribute Queries
     *
     * 3.3.2.3 Element <AttributeQuery>
     * The <AttributeQuery> element is used to make the query “Return the requested attributes for
     * this subject.”
     */
    private fun verifyAttributeQueries() {
        val uniqueAttributeQuery = mutableMapOf<String, String>()
        request.allChildren("AuthnQuery").forEach {
            val name = it.attributes.getNamedItem("Name")
            val nameFormat = it.attributes.getNamedItem("NameFormat")
            if (name != null && nameFormat != null) {
                if (uniqueAttributeQuery.containsKey(name.textContent)
                        && uniqueAttributeQuery[name.textContent] == nameFormat.textContent)
                    throw SAMLComplianceException.create(SAMLCore_3_3_2_3,
                            message = "There were two Attribute Queries with the same nameFormat " +
                                    "of ${nameFormat.textContent} and name of ${name.textContent}.",
                            node = request)
                else uniqueAttributeQuery.put(name.textContent, nameFormat.textContent)
            }
        }
    }

    /**
     * Verify the Authz Decision Queries
     *
     * 3.3.2.4 Element <AuthzDecisionQuery>
     * The <AuthzDecisionQuery> element is used to make the query “Should these actions on this
     * resource be allowed for this subject, given this evidence?”
     */
    private fun verifyAuthzDecisionQueries() {
        request.allChildren("AuthzDecisionQuery").forEach {
            if (it.attributes.getNamedItem("Resource") == null)
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.3.2.4",
                        "Resource",
                        "AuthzDecisionQuery",
                        node = request)

            if (it.children("Action").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore3.3.2.4",
                        "Action",
                        "AuthzDecisionQuery",
                        node = request)
        }
    }

    /**
     * Verify the Authentication Request Protocol
     * 3.4.1.3 Element <IDPList>
     * 3.4.1.3.1 Element <IDPEntry>
     *
     * The <IDPEntry> element specifies a single identity provider trusted by the requester to
     * authenticate the presenter.
     */
    private fun verifyAuthenticationRequestProtocol() {
        // IDPList
        request.allChildren("IDPList").forEach {
            if (it.children("IDPEntry").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.4.1.3",
                        "IDPEntry",
                        "IDPList",
                        node = request)

            //IDPEntry
            it.children("IDPEntry").forEach {
                if (it.attributes.getNamedItem("ProviderID") == null)
                    throw SAMLComplianceException
                            .createWithXmlPropertyReqMessage("SAMLCore.3.4.1.3.1",
                            "ProviderID",
                            "IDPEntry",
                            node = request)
            }
        }
    }

    /**
     * Verify the Artifact Resolution Protocol
     * 3.5.1 Element <ArtifactResolve>
     *
     * The <ArtifactResolve> message is used to request that a SAML protocol message be returned in
     * an <ArtifactResponse> message by specifying an artifact that represents the SAML protocol
     * message.
     */
    private fun verifyArtifactResolutionProtocol() {
        request.allChildren("ArtifactResolve").forEach {
            if (it.children("Artifact").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.5.1",
                        "Artifact",
                        "ArtifactResolve",
                        node = request)
        }
    }

    /**
     * Verify the Manage Name ID Requests
     * 3.6.1 Element <ManageNameIDRequest>
     *
     * This message has the complex type ManageNameIDRequestType, which extends RequestAbstractType
     * and adds the following elements
     */
    private fun verifyManageNameIDRequest() {
        request.allChildren("ManageNameIDRequest").forEach {
            if (it.children("NameID").isEmpty() && it.children("EncryptedID").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.6.1",
                        "NameID or EncryptedID",
                        "ManageNameIDRequest",
                        node = request)

            if (it.children("NewID").isEmpty()
                    && it.children("NewEncryptedID").isEmpty()
                    && it.children("Terminate").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.6.1",
                        "NameID or EncryptedID or Terminate",
                        "ManageNameIDRequest",
                        node = request)
        }
    }

    /**
     * Verify the Name Identifier Mapping Request
     * 3.8.1 Element <NameIDMappingRequest>
     *
     * To request an alternate name identifier for a principal from an identity provider, a
     * requester sends an <NameIDMappingRequest> message.
     */
    private fun verifyNameIdMappingRequest() {
        request.allChildren("NameIDMappingRequest").forEach {
            if (it.children("BaseID").isEmpty()
                    && it.children("NameID").isEmpty()
                    && it.children("EncryptedID").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.8.1",
                        "BaseID or NameID or EncryptedID",
                        "NameIDMappingRequest",
                        node = request)

            if (it.children("NameIDPolicy").isEmpty() && it.children("EncryptedID").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.8.1",
                        "NameIDPolicy",
                        "NameIDMappingRequest",
                        node = request)
        }
    }
}
