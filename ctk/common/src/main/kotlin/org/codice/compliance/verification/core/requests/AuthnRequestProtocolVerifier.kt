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

class AuthnRequestProtocolVerifier (override val request: Node) : RequestProtocolVerifier(request) {
    companion object {
        private const val IDP_ENTRY = "IDPEntry"
        private const val IDP_LIST = "IDPList"
    }

    /** 3.4 Authentication Request Protocol **/
    override fun verify() {
        verifyIdpList()
    }

    /**
     * Verify the Authentication Request Protocol
     * 3.4.1.3 Element <IDPList>
     * 3.4.1.3.1 Element <IDPEntry>
     *
     * The <IDPEntry> element specifies a single identity provider trusted by the requester to
     * authenticate the presenter.
     */
    private fun verifyIdpList() {
        // IDPList
        request.recursiveChildren(IDP_LIST).forEach {
            if (it.children(IDP_ENTRY).isEmpty())
                throw SAMLComplianceException.createWithXmlPropertyReqMessage("SAMLCore.3.4.1.3",
                        property = IDP_ENTRY,
                        parent = IDP_LIST,
                        node = request)

            //IDPEntry
            it.children("IDPEntry").forEach {
                if (it.attributes.getNamedItem("ProviderID") == null)
                    throw SAMLComplianceException
                            .createWithXmlPropertyReqMessage("SAMLCore.3.4.1.3.1",
                                    property = "ProviderID",
                                    parent = IDP_LIST,
                                    node = request)
            }
        }
    }
}
