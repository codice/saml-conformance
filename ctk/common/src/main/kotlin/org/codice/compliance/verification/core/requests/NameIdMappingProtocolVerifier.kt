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
package org.codice.compliance.verification.core.requests

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.verification.core.RequestProtocolVerifier
import org.w3c.dom.Node

class NameIdMappingProtocolVerifier (override val request: Node) :
        RequestProtocolVerifier(request) {
    companion object {
        private const val NAME_ID_MAPPING_REQUEST = "NameIDMappingRequest"
    }

    /** 3.8 Name Identifier Mapping Protocol **/
    override fun verify() {
        verifyNameIdMappingRequest()
    }

    /**
     * Verify the Name Identifier Mapping Request
     * 3.8.1 Element <NameIDMappingRequest>
     *
     * To request an alternate name identifier for a principal from an identity provider, a
     * requester sends an <NameIDMappingRequest> message.
     */
    private fun verifyNameIdMappingRequest() {
        request.allChildren(NAME_ID_MAPPING_REQUEST).forEach {
            if (it.children("BaseID").isEmpty()
                    && it.children("NameID").isEmpty()
                    && it.children("EncryptedID").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.8.1",
                        property = "BaseID or NameID or EncryptedID",
                        parent = NAME_ID_MAPPING_REQUEST,
                        node = request)

            if (it.children("NameIDPolicy").isEmpty() && it.children("EncryptedID").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.8.1",
                        property = "NameIDPolicy",
                        parent = NAME_ID_MAPPING_REQUEST,
                        node = request)
        }
    }
}
