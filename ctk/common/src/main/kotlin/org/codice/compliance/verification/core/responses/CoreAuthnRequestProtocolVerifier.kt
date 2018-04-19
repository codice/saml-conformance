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
import org.codice.compliance.verification.core.NameIDPolicyVerifier
import org.codice.compliance.verification.core.ResponseVerifier
import org.opensaml.saml.saml2.core.NameIDPolicy
import org.w3c.dom.Node

class CoreAuthnRequestProtocolVerifier(override val response: Node,
                                       override val id: String,
                                       override val acsUrl: String?,
                                       private val nameIdPolicy: NameIDPolicy? = null) :
        ResponseVerifier(response, id, acsUrl) {

    val nameIdPolicyVerifier = nameIdPolicy?.let { NameIDPolicyVerifier(response, it) }

    /** 3.4 Authentication Request Protocol **/
    override fun verify() {
        super.verify()
        verifyAuthnRequestProtocolResponse()
        // TODO When DDF is fixed to return NameID format based on NameIDPolicy, uncomment this line
        // nameIdPolicyVerifier?.apply { verify() }
    }

    private fun verifyAuthnRequestProtocolResponse() {
        if (response.children("Assertion")
                        .all { it.children("AuthnStatement").isEmpty() })
            throw SAMLComplianceException.create(SAMLCore_3_4,
                    message = "AuthnStatement not found in any of the Assertions.",
                    node = response)
    }

    override fun verifyEncryptedElements() {
        nameIdPolicyVerifier?.apply { verifyEncryptedIds() }
    }
}
