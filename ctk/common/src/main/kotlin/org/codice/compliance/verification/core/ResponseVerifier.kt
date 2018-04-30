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
import org.codice.compliance.SAMLCore_3_2_2_c
import org.codice.compliance.SAMLCore_3_2_2_d
import org.codice.compliance.SAMLCore_3_2_2_e
import org.codice.compliance.attributeNode
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon.Companion.DESTINATION
import org.codice.compliance.utils.TestCommon.Companion.ID
import org.codice.compliance.utils.TestCommon.Companion.SAML_VERSION
import org.codice.compliance.utils.TestCommon.Companion.STATUS_CODE
import org.codice.compliance.utils.TestCommon.Companion.TOP_LEVEL_STATUS_CODES
import org.codice.compliance.utils.TestCommon.Companion.VERSION
import org.codice.compliance.utils.TestCommon.Companion.acsUrl
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.w3c.dom.Node

abstract class ResponseVerifier(private val samlRequestDom: Node,
                                private val samlResponseDom: Node) : CoreVerifier(samlResponseDom) {

    /** 3.2.2 Complex Type StatusResponseType */
    override fun verify() {
        super.verify()
        verifyStatusResponseType()
        verifyStatusType()
        verifyStatusMessage()
    }

    /** All SAML responses are of types that are derived from the StatusResponseType complex type.*/
    private fun verifyStatusResponseType() {
        CommonDataTypeVerifier.verifyIdValues(samlResponseDom.attributeNode(ID),
                SAMLCore_3_2_2_a)

        // Assuming response is generated in response to a request
        val inResponseTo = samlResponseDom.attributeText("InResponseTo")
        val requestId = samlRequestDom.attributeText(ID)
        if (inResponseTo != null && inResponseTo != requestId)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_2_b,
                    property = "InResponseTo",
                    actual = inResponseTo,
                    expected = requestId,
                    node = samlResponseDom)

        val version = samlResponseDom.attributeNode(VERSION)
        if (version?.textContent != SAML_VERSION)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_2_c,
                    property = VERSION,
                    actual = version?.textContent,
                    expected = SAML_VERSION,
                    node = samlResponseDom)

        CommonDataTypeVerifier.verifyStringValues(version)
        CommonDataTypeVerifier.verifyDateTimeValues(
                samlResponseDom.attributeNode("IssueInstant"), SAMLCore_3_2_2_d)

        samlResponseDom.attributeNode(DESTINATION)?.apply {
            if (textContent != acsUrl[HTTP_POST])
                throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_2_e,
                        property = DESTINATION,
                        actual = textContent,
                        expected = acsUrl[HTTP_POST] ?: "No ACS URL Found",
                        node = samlResponseDom)

            CommonDataTypeVerifier.verifyUriValues(this)
        }

        samlResponseDom.attributeNode("Content")?.let {
            CommonDataTypeVerifier.verifyUriValues(it)
        }
    }

    /** 3.2.2.2 Element <StatusCode> */
    private fun verifyStatusType() {
        if (samlResponseDom.recursiveChildren("Status")
                        .any {
                            !TOP_LEVEL_STATUS_CODES
                                    .contains(it.children(STATUS_CODE).first()
                                            .attributeText("Value"))
                        })
            throw SAMLComplianceException.create(SAMLCore_3_2_2_2_a,
                    SAMLCore_3_2_2_2_a,
                    message = "The first <StatusCode> is not a top level SAML status code.",
                    node = samlResponseDom)

        samlResponseDom.recursiveChildren(STATUS_CODE)
                .map { it.attributeNode("Value") }
                .mapNotNull { CommonDataTypeVerifier.verifyUriValues(it) }
    }

    /** 3.2.2.3 Element <StatusMessage> */
    private fun verifyStatusMessage() {
        samlResponseDom.recursiveChildren("StatusMessage")
                .forEach { CommonDataTypeVerifier.verifyStringValues(it) }
    }
}
