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
import org.codice.compliance.SAMLCore_3_4
import org.codice.compliance.children
import org.codice.compliance.verification.core.ResponseVerifier
import org.w3c.dom.Node

class AuthnRequestProtocolResponseVerifier(override val response: Node,
                                           override val id: String,
                                           override val acsUrl: String?) :
        ResponseVerifier(response, id, acsUrl) {

    /** 3.4 Authentication Request Protocol **/
    override fun verifyProtocolResponse() {
        verifyAuthnRequestProtocolResponse()
    }

    private fun verifyAuthnRequestProtocolResponse() {
        if (response.children("Assertion")
                        .all { it.children("AuthnStatement").isEmpty() })
            throw SAMLComplianceException.create(SAMLCore_3_4,
                    message = "AuthnStatement not found in any of the Assertions.",
                    node = response)
    }
}
