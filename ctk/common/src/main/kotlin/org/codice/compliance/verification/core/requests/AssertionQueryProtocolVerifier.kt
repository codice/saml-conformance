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
package org.codice.compliance.verification.core.requests

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_3_2_2_a
import org.codice.compliance.SAMLCore_3_3_2_2_b
import org.codice.compliance.SAMLCore_3_3_2_3
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.verification.core.RequestProtocolVerifier
import org.w3c.dom.Node

class AssertionQueryProtocolVerifier (override val request: Node) :
        RequestProtocolVerifier(request) {
    companion object {
        private const val AUTHZ_DECISION_QUERY = "AuthzDecisionQuery"
        private const val REQUESTED_AUTHN_CONTEXT = "RequestedAuthnContext"
    }

    /** 3.3 Assertion Query and Request Protocol **/
    override fun verify() {
        verifyAuthnQueries()
        verifyAttributeQueries()
        verifyAuthzDecisionQueries()
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
                            .mapNotNull { auth -> auth.attributes.getNamedItem("SessionIndex") }
                            .map { sidx -> sidx.textContent }
                            .none { t -> t == querySessionIndex }) {
                throw SAMLComplianceException.create(SAMLCore_3_3_2_2_a,
                        message = "There was no AuthnStatement in the Assertion that had a " +
                                "SessionsIndex of $querySessionIndex.",
                        node = request)
            }

            //RequestedAuthnContext
            it.children(REQUESTED_AUTHN_CONTEXT).forEach { verifyRequestedAuthnContext(it) }

            // todo - verify correctness (brandan - I think this is correct but missing a last step:
            // "<AuthnContext>
            // element that satisfies the element in the query")
            if (it.children(REQUESTED_AUTHN_CONTEXT).isNotEmpty()
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
                    property = "AuthnContextClassRef or AuthnContextDeclRef",
                    parent = REQUESTED_AUTHN_CONTEXT,
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
                else uniqueAttributeQuery[name.textContent] = nameFormat.textContent
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
                        property = "Resource",
                        parent = AUTHZ_DECISION_QUERY,
                        node = request)

            if (it.children("Action").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore3.3.2.4",
                        property = "Action",
                        parent = AUTHZ_DECISION_QUERY,
                        node = request)
        }
    }
}
