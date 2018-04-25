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
import org.codice.compliance.utils.TestCommon.Companion.SAML_VERSION
import org.codice.compliance.utils.TestCommon.Companion.TOP_LEVEL_STATUS_CODES
import org.codice.compliance.utils.decorators.IdpResponseDecorator
import org.codice.security.sign.SimpleSign

abstract class ResponseVerifier(open val response: IdpResponseDecorator,
                                open val id: String,
                                open val acsUrl: String?) : CoreVerifier(response) {
    companion object {
        private const val VERSION = "Version"
        private const val DESTINATION = "Destination"
        private const val STATUS_CODE = "StatusCode"
    }

    private val responseDom by lazy {
        response.responseDom
    }

    private val responseObject by lazy {
        response.responseObject
    }

    /** 3.2.2 Complex Type StatusResponseType */
    override fun verify() {
        super.verify()
        verifyStatusResponseType()
        verifyStatusType()
        verifyStatusMessage()
    }

    /** All SAML responses are of types that are derived from the StatusResponseType complex type.*/
    private fun verifyStatusResponseType() {
        CommonDataTypeVerifier.verifyIdValues(responseDom.attributeNode("ID"),
                SAMLCore_3_2_2_a)

        // Assuming response is generated in response to a request
        val inResponseTo = responseDom.attributeText("InResponseTo")
        if (inResponseTo != null && inResponseTo != id)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_2_b,
                    property = "InResponseTo",
                    actual = inResponseTo,
                    expected = id,
                    node = responseDom)

        val version = responseDom.attributeNode(VERSION)
        if (version?.textContent != SAML_VERSION)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_2_c,
                    property = VERSION,
                    actual = version?.textContent,
                    expected = SAML_VERSION,
                    node = responseDom)

        CommonDataTypeVerifier.verifyStringValues(version)
        CommonDataTypeVerifier.verifyDateTimeValues(
                responseDom.attributeNode("IssueInstant"), SAMLCore_3_2_2_d)

        responseDom.attributeNode(DESTINATION)?.apply {
            if (textContent != acsUrl)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_2_e,
                        property = DESTINATION,
                        actual = textContent,
                        expected = acsUrl ?: "No ACS URL Found",
                        node = responseDom)

            CommonDataTypeVerifier.verifyUriValues(this)
        }

        responseDom.attributeNode("Content")?.let {
            CommonDataTypeVerifier.verifyUriValues(it)
        }

        if (responseObject.isSigned) SimpleSign().validateSignature(responseObject.signature)
    }

    /** 3.2.2.2 Element <StatusCode> */
    private fun verifyStatusType() {
        if (responseDom.recursiveChildren("Status")
                        .any {
                            !TOP_LEVEL_STATUS_CODES
                                    .contains(it.children(STATUS_CODE).first()
                                            .attributeText("Value"))
                        })
            throw SAMLComplianceException.create(SAMLCore_3_2_2_2_a,
                    SAMLCore_3_2_2_2,
                    message = "The first <StatusCode> is not a top level SAML status code.",
                    node = responseDom)

        responseDom.recursiveChildren(STATUS_CODE)
                .map { it.attributeNode("Value") }
                .filterNotNull()
                .forEach { CommonDataTypeVerifier.verifyUriValues(it) }
    }

    /** 3.2.2.3 Element <StatusMessage> */
    private fun verifyStatusMessage() {
        responseDom.recursiveChildren("StatusMessage")
                .forEach { CommonDataTypeVerifier.verifyStringValues(it) }
    }
}
