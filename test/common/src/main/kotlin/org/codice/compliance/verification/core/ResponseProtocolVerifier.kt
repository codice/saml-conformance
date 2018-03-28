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
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_3_2_2_2
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_3_2_2_a
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_3_2_2_b
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_3_2_2_c
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_3_2_2_d
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_3_2_2_e
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_3_4
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.w3c.dom.Node

class ResponseProtocolVerifier(private val response: Node, private val id: String, private val acsUrl: String?) {
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
        CoreVerifier(response).verify()
        verifyStatusResponseType()
        verifyStatusesType()
        verifyNameIdMappingResponse()

        // 3.4 Authentication Request Protocol
        // todo - verify if this common for everything
        response.children("Assertion")
                .forEach {
                    if (it.children("AuthnStatement").isEmpty())
                        throw SAMLComplianceException.create(SAMLCore_3_4,
                                message = "AuthnStatement not found.",
                                node = response)
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
            throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.2.2", "ID", "Response", node = response)
        verifyIdValues(response.attributes.getNamedItem("ID"), SAMLCore_3_2_2_a)

        // Assuming response is generated in response to a request
        val inResponseTo = response.attributes?.getNamedItem("InResponseTo")?.textContent
        if (inResponseTo != id)
            throw SAMLComplianceException.createWithPropertyMessage(code = SAMLCore_3_2_2_b,
                    property = "InResponseTo",
                    actual = inResponseTo,
                    expected = id,
                    node = response)

        if (response.attributes.getNamedItem("Version") == null)
            throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.2.2",
                    "Version",
                    "Response",
                    node = response)

        val version = response.attributes?.getNamedItem("Version")?.textContent
        if (version != "2.0")
            throw SAMLComplianceException.createWithPropertyMessage(code = SAMLCore_3_2_2_c,
                    property = "Version",
                    actual = version,
                    expected = "2.0",
                    node = response)

        if (response.attributes.getNamedItem("IssueInstant") == null)
            throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.2.2",
                    "IssueInstant",
                    "Response",
                    node = response)
        verifyTimeValues(response.attributes.getNamedItem("IssueInstant"), SAMLCore_3_2_2_d)

        val destination = response.attributes?.getNamedItem("Destination")?.textContent
        if (destination != acsUrl)
            throw SAMLComplianceException.createWithPropertyMessage(code = SAMLCore_3_2_2_e,
                    property = "Destination",
                    actual = destination,
                    expected = acsUrl ?: "No ACS URL Found",
                    node = response)

        if (response.children("Status").isEmpty())
            throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.2.2",
                    "Status",
                    "Response",
                    node = response)
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
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.2.2.1", "StatusCode", "Status", node = response)

            // StatusCode
            if (statusCodes.any { it.attributes.getNamedItem("Value") == null })
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.2.2.2", "Value", "StatusCode", node = response)

            val statusCode = statusCodes[0].attributes?.getNamedItem("Value")?.textContent
            if (!TOP_LEVEL_STATUS_CODES.contains(statusCode))
                throw SAMLComplianceException.createWithPropertyMessage(code = SAMLCore_3_2_2_2,
                        property = "Status Code",
                        actual = statusCode,
                        node = response)
        }
    }

    /**
     * Verify the Name Identifier Mapping Protocol
     * 3.8.2 Element <NameIDMappingResponse>
     */
    private fun verifyNameIdMappingResponse() {
        response.allChildren("NameIDMappingResponse").forEach {
            if (it.children("NameID").isEmpty() && it.children("EncryptedID").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.6.1",
                        "NameID or EncryptedID",
                        "NameIDMappingResponse",
                        node = response)
        }
    }
}
