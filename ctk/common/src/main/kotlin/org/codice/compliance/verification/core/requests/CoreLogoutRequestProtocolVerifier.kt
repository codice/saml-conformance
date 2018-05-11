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

import org.codice.compliance.SAMLCore_3_7_1_a
import org.codice.compliance.attributeNode
import org.codice.compliance.verification.core.CommonDataTypeVerifier
import org.codice.compliance.verification.core.RequestVerifier
import org.w3c.dom.Node

class CoreLogoutRequestProtocolVerifier(private val samlRequestDom: Node) :
    RequestVerifier(samlRequestDom) {

    /** 3.7.1 Element <LogoutRequest>*/
    override fun verify() {
        verifyLogoutRequest()
        super.verify()
    }

    private fun verifyLogoutRequest() {
        samlRequestDom.attributeNode("Reason")?.let {
            CommonDataTypeVerifier.verifyUriValue(it, SAMLCore_3_7_1_a)
        }

        samlRequestDom.attributeNode("NotOnOrAfter")?.let {
            CommonDataTypeVerifier.verifyDateTimeValue(it)
        }
    }
}
