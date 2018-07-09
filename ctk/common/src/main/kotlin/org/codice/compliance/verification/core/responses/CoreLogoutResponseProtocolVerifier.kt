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
package org.codice.compliance.verification.core.responses

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_7_3_2_b
import org.codice.compliance.SAMLCore_3_7_3_2_d
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.utils.STATUS
import org.codice.compliance.utils.STATUS_CODE
import org.codice.compliance.verification.core.ResponseVerifier
import org.codice.security.saml.SamlProtocol
import org.opensaml.saml.saml2.core.LogoutRequest

class CoreLogoutResponseProtocolVerifier(logoutRequest: LogoutRequest,
                                         private val samlResponse: NodeDecorator,
                                         binding: SamlProtocol.Binding,
                                         private val expectedSecondLevelStatusCode: String? = null)
    : ResponseVerifier(logoutRequest, samlResponse, binding) {

    override fun verify() {
        super.verify()
        verifySecondaryStatusCode()
    }

    private fun verifySecondaryStatusCode() {
        val secondaryStatusCode = samlResponse.children(STATUS)
                .flatMap { it.children(STATUS_CODE) }
                .firstOrNull()
                ?.children(STATUS_CODE)
                ?.firstOrNull()
                ?.attributeText("Value")

        if (expectedSecondLevelStatusCode != null
                && secondaryStatusCode != expectedSecondLevelStatusCode)
            throw SAMLComplianceException.create(SAMLCore_3_7_3_2_b,
                    SAMLCore_3_7_3_2_d,
                    message = "The status code of $expectedSecondLevelStatusCode was not found",
                    node = samlResponse)
    }
}
