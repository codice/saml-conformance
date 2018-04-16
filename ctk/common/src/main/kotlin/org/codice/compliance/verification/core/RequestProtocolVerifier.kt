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
import org.codice.compliance.children
import org.w3c.dom.Node

abstract class RequestProtocolVerifier(open val request: Node) {
    companion object {
        private const val ID = "ID"
        private const val VERSION = "Version"
        private const val ISSUE_INSTANT = "IssueInstant"
        private const val REQUEST = "Request"
        private const val SAML_VERSION = "2.0"
        private const val SAMLCore_3_2_1 = "SAMLCore.3.2.1"
    }

    /**
     * Verify protocols against the Core Spec document
     * 3.2.1 Complex Type StatusResponseType
     */
    fun verifyCoreRequestProtocol() {
        CoreVerifier(request).verify()
        verifyRequestAbstractType()
        verify()
    }

    abstract fun verify()

    /**
     * Verify the Request Abstract Types
     * 3.2.1 Complex Type RequestAbstractType
     * All SAML requests are of types that are derived from the abstract RequestAbstractType
     * complex type.
     */
    private fun verifyRequestAbstractType() {
        if (request.attributes.getNamedItem(ID) == null)
            throw SAMLComplianceException.createWithXmlPropertyReqMessage(SAMLCore_3_2_1,
                    property = ID,
                    parent = REQUEST,
                    node = request)
        CommonDataTypeVerifier.verifyIdValues(request.attributes.getNamedItem(ID), SAMLCore_3_2_1_a)

        if (request.attributes.getNamedItem(VERSION) == null)
            throw SAMLComplianceException.createWithXmlPropertyReqMessage(SAMLCore_3_2_1,
                    property = VERSION,
                    parent = REQUEST,
                    node = request)

        if (request.attributes.getNamedItem(VERSION).textContent != SAML_VERSION)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_3_2_1_b,
                    property = VERSION,
                    actual = request.attributes.getNamedItem(VERSION).textContent,
                    expected = SAML_VERSION,
                    node = request)

        if (request.attributes.getNamedItem(ISSUE_INSTANT) == null)
            throw SAMLComplianceException.createWithXmlPropertyReqMessage(SAMLCore_3_2_1,
                    property = ISSUE_INSTANT,
                    parent = REQUEST,
                    node = request)
        CommonDataTypeVerifier.verifyDateTimeValues(request.attributes.getNamedItem(ISSUE_INSTANT),
                SAMLCore_3_2_1_c)

        CoreVerifier.verifySamlExtensions(request.children(),
                expectedSamlNames = listOf("Issuer", "Signature"))
    }
}
