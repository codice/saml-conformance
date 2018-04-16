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
import org.codice.compliance.SAMLCore_3_2_2_2
import org.codice.compliance.SAMLCore_3_2_2_a
import org.codice.compliance.SAMLCore_3_2_2_b
import org.codice.compliance.SAMLCore_3_2_2_c
import org.codice.compliance.SAMLCore_3_2_2_d
import org.codice.compliance.SAMLCore_3_2_2_e
import org.codice.compliance.SAMLCore_3_4
import org.codice.compliance.recursiveChildren
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon.Companion.SAML_VERSION
import org.codice.compliance.utils.TestCommon.Companion.TOP_LEVEL_STATUS_CODES
import org.w3c.dom.Node

class ResponseProtocolVerifier(private val response: Node,
                               private val id: String,
                               private val acsUrl: String?) {
    companion object {
        private const val ID = "ID"
        private const val VALUE = "Value"
        private const val STATUS = "Status"
        private const val VERSION = "Version"
        private const val RESPONSE = "Response"
        private const val STATUS_CODE = "StatusCode"
        private const val ISSUE_INSTANT = "IssueInstant"
        private const val SAMLCore_3_2_2 = "SAMLCore.3.2.2"
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

        if (response.localName == "AuthnRequest") {
            response.children("Assertion")
                    .forEach {
                        if (it.children("AuthnStatement").isEmpty())
                            throw SAMLComplianceException.create(SAMLCore_3_4,
                                    message = "AuthnStatement not found.",
                                    node = response)
                    }
        }
    }

    /**
     * Verify the Status Response Type
     * 3.2.2 Complex Type StatusResponseType
     *
     * All SAML responses are of types that are derived from the StatusResponseType complex type.
     */
    private fun verifyStatusResponseType() {
        if (response.attributes.getNamedItem(ID) == null)
            throw SAMLComplianceException.createWithXmlPropertyReqMessage(SAMLCore_3_2_2,
                    property = ID,
                    parent = RESPONSE,
                    node = response)
        CommonDataTypeVerifier.verifyIdValues(response.attributes.getNamedItem(ID),
                SAMLCore_3_2_2_a)

        // Assuming response is generated in response to a request
        val inResponseTo = response.attributes?.getNamedItem("InResponseTo")?.textContent
        if (inResponseTo != id)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_2_b,
                    property = "InResponseTo",
                    actual = inResponseTo,
                    expected = id,
                    node = response)

        if (response.attributes.getNamedItem(VERSION) == null)
            throw SAMLComplianceException.createWithXmlPropertyReqMessage(SAMLCore_3_2_2,
                    property = VERSION,
                    parent = RESPONSE,
                    node = response)

        val version = response.attributes?.getNamedItem(VERSION)?.textContent
        if (version != SAML_VERSION)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_2_c,
                    property = VERSION,
                    actual = version,
                    expected = SAML_VERSION,
                    node = response)

        if (response.attributes.getNamedItem(ISSUE_INSTANT) == null)
            throw SAMLComplianceException.createWithXmlPropertyReqMessage(SAMLCore_3_2_2,
                    property = ISSUE_INSTANT,
                    parent = RESPONSE,
                    node = response)
        CommonDataTypeVerifier.verifyDateTimeValues(
                response.attributes.getNamedItem(ISSUE_INSTANT), SAMLCore_3_2_2_d)

        val destination = response.attributes?.getNamedItem("Destination")?.textContent
        if (destination != acsUrl)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_2_e,
                    property = "Destination",
                    actual = destination,
                    expected = acsUrl ?: "No ACS URL Found",
                    node = response)

        if (response.children(STATUS).isEmpty())
            throw SAMLComplianceException.createWithXmlPropertyReqMessage(SAMLCore_3_2_2,
                    property = STATUS,
                    parent = RESPONSE,
                    node = response)

        CoreVerifier.verifySamlExtensions(response.children(),
                expectedSamlNames = listOf("Issuer", "Signature", "Status", "Assertion",
                        "EncryptedAssertion"))
    }

    /**
     * Verify the Statuses and Status Codes
     * 3.2.2.1 Element <Status>
     * 3.2.2.2 Element <StatusCode>
     */
    private fun verifyStatusesType() {
        // Status
        response.children(STATUS).forEach {
            val statusCodes = it.children(STATUS_CODE)
            if (statusCodes.isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.2.2.1",
                        property = STATUS_CODE,
                        parent = STATUS,
                        node = response)

            // StatusCode
            if (statusCodes.any { it.attributes.getNamedItem(VALUE) == null })
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.2.2.2",
                        property = VALUE,
                        parent = STATUS_CODE,
                        node = response)

            val statusCode = statusCodes[0].attributes.getNamedItem(VALUE).textContent
            if (!TOP_LEVEL_STATUS_CODES.contains(statusCode))
                throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_2_2,
                        property = STATUS_CODE,
                        actual = statusCode,
                        node = response)
        }
    }

    /**
     * Verify the Name Identifier Mapping Protocol
     * 3.8.2 Element <NameIDMappingResponse>
     */
    private fun verifyNameIdMappingResponse() {
        response.recursiveChildren("NameIDMappingResponse").forEach {
            if (it.children("NameID").isEmpty() && it.children("EncryptedID").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.6.1",
                        property = "NameID or EncryptedID",
                        parent = "NameIDMappingResponse",
                        node = response)
        }
    }
}
