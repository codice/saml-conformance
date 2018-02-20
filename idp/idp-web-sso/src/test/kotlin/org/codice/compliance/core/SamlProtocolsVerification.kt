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
package org.codice.compliance.core

import org.codice.compliance.ID
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.children
import org.w3c.dom.Node

/**
 * Verify protocols against the Core Spec document
 * 2 SAML Assertions
 */
fun verifyProtocols(response: Node) {
    verifyStatuses(response)
}

/**
 * Verify the Statuses
 * 3.2.2 Complex Type StatusResponseType
 * 3.2.2.1 Element <Status>
 */
fun verifyStatuses(response: Node) {
    // StatusResponseType
    if (response.attributes.getNamedItem("ID") == null)
        throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.2.2", "ID", "Response")

    // Assuming response is generated in response to a request
    val inResponseTo = response.attributes.getNamedItem("InResponseTo")
    if (inResponseTo == null || inResponseTo.textContent != ID)
        throw SAMLComplianceException.create("SAMLCore.3.2.2_a")

    if (response.attributes.getNamedItem("Version").textContent != "2.0")
        throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.2.2", "Version", "Response")

    if (response.attributes.getNamedItem("IssueInstant") == null)
        throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.2.2", "IssueInstant", "Response")

    if (response.children("Status").isEmpty())
        throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.2.2", "Status", "Response")


    // Status
    val statuses = response.children("Status")
    statuses.forEach {
        if (it.children("StatusCode").isEmpty())
            throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.2.2.1", "StatusCode", "Status")
    }
}