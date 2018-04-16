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
import org.codice.compliance.recursiveChildren
import org.codice.compliance.children
import org.codice.compliance.verification.core.RequestProtocolVerifier
import org.w3c.dom.Node

class NameIdManagementProtocolVerifier (override val request: Node) :
        RequestProtocolVerifier(request) {
    companion object {
        private const val MANAGE_NAME_ID_REQUEST = "ManageNameIDRequest"
    }

    /** 3.6 Name Identifier Management Protocol **/
    override fun verify() {
        verifyManageNameIDRequest()
    }

    /**
     * Verify the Manage Name ID Requests
     * 3.6.1 Element <ManageNameIDRequest>
     *
     * This message has the complex type ManageNameIDRequestType, which extends RequestAbstractType
     * and adds the following elements
     */
    private fun verifyManageNameIDRequest() {
        request.recursiveChildren(MANAGE_NAME_ID_REQUEST).forEach {
            if (it.children("NameID").isEmpty() && it.children("EncryptedID").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.6.1",
                        property = "NameID or EncryptedID",
                        parent = MANAGE_NAME_ID_REQUEST,
                        node = request)

            if (it.children("NewID").isEmpty()
                    && it.children("NewEncryptedID").isEmpty()
                    && it.children("Terminate").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.6.1",
                        property = "NameID or EncryptedID or Terminate",
                        parent = MANAGE_NAME_ID_REQUEST,
                        node = request)
        }
    }
}
