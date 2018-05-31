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
import org.codice.compliance.utils.DESTINATION
import org.codice.compliance.utils.ID
import org.codice.compliance.utils.STATUS
import org.codice.compliance.utils.STATUS_CODE
import org.codice.compliance.utils.SUCCESS
import org.codice.compliance.utils.TestCommon.Companion.getServiceUrl
import org.codice.compliance.utils.VERSION
import org.codice.compliance.utils.topLevelStatusCodes
import org.codice.security.saml.SamlProtocol
import org.opensaml.saml.saml2.core.RequestAbstractType
import org.w3c.dom.Node

abstract class ResponseVerifier(private val samlRequest: RequestAbstractType,
                                protected val samlResponseDom: Node,
                                private val binding: SamlProtocol.Binding) :
        CoreVerifier(samlResponseDom) {

    /** 3.2.2 Complex Type StatusResponseType */
    override fun verify() {
        super.verify()
        verifyStatusResponseType()
        verifyStatusType()
        verifyStatusMessage()
    }

    /** All SAML responses are of types that are derived from the StatusResponseType complex type.*/
    private fun verifyStatusResponseType() {
        CommonDataTypeVerifier.verifyIdValue(samlResponseDom.attributeNode(ID),
                SAMLCore_3_2_2_a)

        // Assuming response is generated in response to a request
        val inResponseTo = samlResponseDom.attributeText("InResponseTo")
        val requestId = samlRequest.id
        if (inResponseTo != null && inResponseTo != requestId)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_2_b,
                    property = "InResponseTo",
                    actual = inResponseTo,
                    expected = requestId,
                    node = samlResponseDom)

        CommonDataTypeVerifier.verifyStringValue(samlResponseDom.attributeNode(VERSION))
        CommonDataTypeVerifier.verifyDateTimeValue(
                samlResponseDom.attributeNode("IssueInstant"), SAMLCore_3_2_2_d)

        samlResponseDom.attributeNode(DESTINATION)?.apply {

            val url = getServiceUrl(binding, samlResponseDom)
            if (textContent != url)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_2_e,
                        property = DESTINATION,
                        actual = textContent,
                        expected = url ?: "No ACS URL Found",
                        node = samlResponseDom)

            CommonDataTypeVerifier.verifyUriValue(this)
        }

        samlResponseDom.attributeNode("Content")?.let {
            CommonDataTypeVerifier.verifyUriValue(it)
        }
    }

    /** 3.2.2.2 Element <StatusCode> */
    private fun verifyStatusType() {
        val topLevelStatusCode = samlResponseDom.recursiveChildren(STATUS)
            .flatMap { it.children(STATUS_CODE) }
            .first()
            .attributeText("Value")
        if (!topLevelStatusCodes.contains(topLevelStatusCode))
            throw SAMLComplianceException.create(SAMLCore_3_2_2_2_a,
                    message = "The StatusCode value of $topLevelStatusCode is not a top level " +
                        "SAML status code.",
                    node = samlResponseDom)

        if (topLevelStatusCode != SUCCESS)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLGeneral_e,
                    property = STATUS_CODE,
                    expected = SUCCESS,
                    actual = topLevelStatusCode,
                    node = samlResponseDom)

        samlResponseDom.recursiveChildren(STATUS_CODE)
                .mapNotNull { it.attributeNode("Value") }
                .forEach { CommonDataTypeVerifier.verifyUriValue(it) }
    }

    /** 3.2.2.3 Element <StatusMessage> */
    private fun verifyStatusMessage() {
        samlResponseDom.recursiveChildren("StatusMessage")
                .forEach { CommonDataTypeVerifier.verifyStringValue(it) }
    }
}
