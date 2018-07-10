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
import org.codice.compliance.SAMLCore_3_2_1_e
import org.codice.compliance.attributeNode
import org.codice.compliance.utils.CONSENT
import org.codice.compliance.utils.DESTINATION
import org.codice.compliance.utils.ID
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.utils.TestCommon.Companion.getServiceUrl
import org.codice.compliance.utils.VERSION
import org.codice.security.saml.SamlProtocol

abstract class RequestVerifier(private val samlRequest: NodeDecorator,
                               private val binding: SamlProtocol.Binding)
    : CoreVerifier(samlRequest) {

    /** 3.2.1 Complex Type RequestAbstractType */
    override fun verify() {
        verifyRequestAbstractType()
        super.verify()
    }

    /** All SAML requests are of types that are derived from the abstract RequestAbstractType
     * complex type. */
    private fun verifyRequestAbstractType() {
        CommonDataTypeVerifier.verifyIdValue(samlRequest.attributeNode(ID), SAMLCore_3_2_1_a)
        CommonDataTypeVerifier.verifyStringValue(samlRequest.attributeNode(VERSION),
                SAMLCore_3_2_1_b)
        CommonDataTypeVerifier.verifyDateTimeValue(
                samlRequest.attributeNode("IssueInstant"), SAMLCore_3_2_1_c)

        samlRequest.attributeNode(DESTINATION)?.apply {

            val url = getServiceUrl(binding, samlRequest)
            if (textContent != url)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_1_e,
                        property = DESTINATION,
                        actual = textContent,
                        expected = url,
                        node = samlRequest)

            CommonDataTypeVerifier.verifyUriValue(this)
        }

        samlRequest.attributeNode(CONSENT)?.let {
            CommonDataTypeVerifier.verifyUriValue(it)
        }
    }
}
