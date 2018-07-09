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
import org.codice.compliance.SAMLCore_3_2_2_2_a
import org.codice.compliance.SAMLCore_3_2_2_a
import org.codice.compliance.SAMLCore_3_2_2_b
import org.codice.compliance.SAMLCore_3_2_2_d
import org.codice.compliance.SAMLCore_3_2_2_e
import org.codice.compliance.SAMLGeneral_e
import org.codice.compliance.attributeNode
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.CONSENT
import org.codice.compliance.utils.DESTINATION
import org.codice.compliance.utils.ID
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.utils.STATUS
import org.codice.compliance.utils.STATUS_CODE
import org.codice.compliance.utils.SUCCESS
import org.codice.compliance.utils.TestCommon.Companion.getServiceUrl
import org.codice.compliance.utils.VERSION
import org.codice.compliance.utils.topLevelStatusCodes
import org.codice.security.saml.SamlProtocol
import org.opensaml.saml.saml2.core.RequestAbstractType

abstract class ResponseVerifier(private val samlRequest: RequestAbstractType,
                                private val samlResponse: NodeDecorator,
                                private val binding: SamlProtocol.Binding) :
        CoreVerifier(samlResponse) {

    /** 3.2.2 Complex Type StatusResponseType */
    override fun verify() {
        verifyStatusResponseType()
        verifyStatusCode()
        verifyStatusMessage()
        super.verify()
    }

    /** All SAML responses are of types that are derived from the StatusResponseType complex type.*/
    private fun verifyStatusResponseType() {
        CommonDataTypeVerifier.verifyIdValue(samlResponse.attributeNode(ID),
                SAMLCore_3_2_2_a)

        // Assuming response is generated in response to a request
        val inResponseTo = samlResponse.attributeText("InResponseTo")
        val requestId = samlRequest.id
        if (inResponseTo != null && inResponseTo != requestId)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_2_b,
                    property = "InResponseTo",
                    actual = inResponseTo,
                    expected = requestId,
                    node = samlResponse)

        CommonDataTypeVerifier.verifyStringValue(samlResponse.attributeNode(VERSION))
        CommonDataTypeVerifier.verifyDateTimeValue(
                samlResponse.attributeNode("IssueInstant"), SAMLCore_3_2_2_d)

        samlResponse.attributeNode(DESTINATION)?.apply {

            val url = getServiceUrl(binding, samlResponse)
            if (textContent != url)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_2_e,
                        property = DESTINATION,
                        actual = textContent,
                        expected = url ?: "No ACS URL Found",
                        node = samlResponse)

            CommonDataTypeVerifier.verifyUriValue(this)
        }

        samlResponse.attributeNode(CONSENT)?.let {
            CommonDataTypeVerifier.verifyUriValue(it)
        }
    }

    /** 3.2.2.2 Element <StatusCode> */
    private fun verifyStatusCode() {
        val topLevelStatusCode = samlResponse.recursiveChildren(STATUS)
                .flatMap { it.children(STATUS_CODE) }
                .first()
                .attributeText("Value")
        if (!topLevelStatusCodes.contains(topLevelStatusCode))
            throw SAMLComplianceException.create(SAMLCore_3_2_2_2_a,
                    message = "The StatusCode value of $topLevelStatusCode is not a top level " +
                            "SAML status code.",
                    node = samlResponse)

        if (topLevelStatusCode != SUCCESS)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLGeneral_e,
                    property = STATUS_CODE,
                    expected = SUCCESS,
                    actual = topLevelStatusCode,
                    node = samlResponse)

        samlResponse.recursiveChildren(STATUS_CODE)
                .mapNotNull { it.attributeNode("Value") }
                .forEach { CommonDataTypeVerifier.verifyUriValue(it) }
    }

    /** 3.2.2.3 Element <StatusMessage> */
    private fun verifyStatusMessage() {
        samlResponse.recursiveChildren("StatusMessage")
                .forEach { CommonDataTypeVerifier.verifyStringValue(it) }
    }
}
