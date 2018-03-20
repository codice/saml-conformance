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
import org.codice.compliance.SAMLSpecRefMessage.*
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon.Companion.ACS_URL
import org.w3c.dom.Node

class ResponseProtocolVerifier(val response: Node, val id: String) {
    companion object {
        private val TOP_LEVEL_STATUS_CODES = setOf("urn:oasis:names:tc:SAML:2.0:status:Success",
                "urn:oasis:names:tc:SAML:2.0:status:Requester",
                "urn:oasis:names:tc:SAML:2.0:status:Responder",
                "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch")
    }

    /**
     * Verify protocols against the Core Spec document
     * 3.2.2 Complex Type StatusResponseType
     */
    fun verify() {
        verifyStatusResponseType()
        verifyStatusesType()
        verifyNameIdMappingResponse()

        // 3.4 Authentication Request Protocol
        // todo - verify if this common for everything
        response.children("Assertion")
                .forEach {
                    if (it.children("AuthnStatement").isEmpty())
                        throw SAMLComplianceException.create(SAMLCore_3_4, message = "AuthnStatement not found.")
                }
    }

    /**
     * Verify the Status Response Type
     * 3.2.2 Complex Type StatusResponseType
     *
     * All SAML responses are of types that are derived from the StatusResponseType complex type.
     */
    private fun verifyStatusResponseType() {
        if (response.attributes.getNamedItem("ID") == null)
            throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.3.2.2", "ID", "Response")
        verifyIdValues(response.attributes.getNamedItem("ID"), SAMLCore_3_2_2_a)

        // Assuming response is generated in response to a request
        val inResponseTo = response.attributes?.getNamedItem("InResponseTo")?.textContent
        if (inResponseTo != id)
            throw SAMLComplianceException.createWithPropertyNotEqualMessage(SAMLCore_3_2_2_b,
                    "InResponseTo",
                    inResponseTo,
                    id)

        if (response.attributes.getNamedItem("Version") == null)
            throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.3.2.2",
                    "Version",
                    "Response")

        val version = response.attributes?.getNamedItem("Version")?.textContent
        if (version != "2.0")
            throw SAMLComplianceException.createWithPropertyNotEqualMessage(SAMLCore_3_2_2_c,
                    "Version",
                    version,
                    "2.0")

        if (response.attributes.getNamedItem("IssueInstant") == null)
            throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.3.2.2",
                    "IssueInstant",
                    "Response")
        verifyTimeValues(response.attributes.getNamedItem("IssueInstant"), SAMLCore_3_2_2_d)

        val destination = response.attributes?.getNamedItem("Destination")?.textContent
        if (destination != ACS_URL)
            throw SAMLComplianceException.createWithPropertyNotEqualMessage(SAMLCore_3_2_2_e,
                    "Destination",
                    destination,
                    ACS_URL)

        if (response.children("Status").isEmpty())
            throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.3.2.2",
                    "Status",
                    "Response")
    }

    /**
     * Verify the Statuses and Status Codes
     * 3.2.2.1 Element <Status>
     * 3.2.2.2 Element <StatusCode>
     */
    private fun verifyStatusesType() {
        // Status
        response.children("Status").forEach {
            val statusCodes = it.children("StatusCode")
            if (statusCodes.isEmpty())
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.3.2.2.1", "StatusCode", "Status")

            // StatusCode
            if (statusCodes.any { it.attributes.getNamedItem("Value") == null })
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.3.2.2.2", "Value", "StatusCode")

            val statusCode = statusCodes[0].attributes?.getNamedItem("Value")?.textContent
            if (!TOP_LEVEL_STATUS_CODES.contains(statusCode))
                throw SAMLComplianceException.createWithPropertyInvalidMessage(SAMLCore_3_2_2_2,
                        "Status Code",
                        statusCode)
        }
    }

    /**
     * Verify the Name Identifier Mapping Protocol
     * 3.8.2 Element <NameIDMappingResponse>
     */
    private fun verifyNameIdMappingResponse() {
        response.allChildren("NameIDMappingResponse").forEach {
            if (it.children("NameID").isEmpty() && it.children("EncryptedID").isEmpty())
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.3.6.1",
                        "NameID or EncryptedID",
                        "NameIDMappingResponse")
        }
    }
}
