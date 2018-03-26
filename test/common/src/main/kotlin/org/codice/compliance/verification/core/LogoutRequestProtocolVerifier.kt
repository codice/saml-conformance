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
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_3_7_1
import org.codice.compliance.children
import org.w3c.dom.Node

class LogoutRequestProtocolVerifier(val request: Node) {
    /**
     * Verify Logout Request Protocol against the Core document
     * 3.7.1 Element <LogoutRequest>
     */
    fun verifyLogoutRequestProtocol() {
        request.children("LogoutRequest").forEach {
            if (it.attributes.getNamedItem("Reason") != null)
                verifyUriValues(it.attributes.getNamedItem("Reason"), SAMLCore_3_7_1)

            if (it.children("BaseID").isEmpty()
                    && it.children("NameID").isEmpty()
                    && it.children("EncryptedID").isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.7.1",
                        "BaseID or NameID or EncryptedID",
                        "LogoutRequest")
        }
    }
}
