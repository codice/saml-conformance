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
import org.codice.compliance.SAMLCore_2_2_4_a
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon.Companion.ELEMENT
import org.codice.compliance.verification.core.internal.AssertionsVerifier
import org.codice.compliance.verification.core.internal.ConditionsVerifier
import org.codice.compliance.verification.core.internal.StatementVerifier
import org.codice.compliance.verification.core.internal.SubjectVerifier
import org.w3c.dom.Node

class SamlAssertionsVerifier(val node: Node) {
    companion object {
        private const val ENCRYPTED_ID = "EncryptedID"
    }
    /**
     * Verify assertions against the Core Spec document
     * 2 SAML Assertions
     */
    fun verify() {
        verifyNameIdentifiers()
        AssertionsVerifier(node).verify()
        SubjectVerifier(node).verify()
        ConditionsVerifier(node).verify()
        StatementVerifier(node).verify()
    }

    /**
     * Verify the Name Identifiers against the Core Spec document
     * 2.2 Name Identifiers
     * 2.2.4 Element <EncryptedID>
     */
    private fun verifyNameIdentifiers() {
        // EncryptedID
        node.allChildren(ENCRYPTED_ID).forEach {
            val encryptedData = it.children("EncryptedData")
            if (encryptedData.isEmpty()) throw SAMLComplianceException
                    .createWithXmlPropertyReqMessage("SAMLCore.2.2.4",
                            property = "EncryptedData",
                            parent = ENCRYPTED_ID)

            if (encryptedData.filter { it.attributes.getNamedItem("Type") != null }
                            .any { it.attributes.getNamedItem("Type").textContent != ELEMENT })
                throw SAMLComplianceException.create(SAMLCore_2_2_4_a,
                        message = "Type attribute found with an incorrect value.",
                        node = node)
        }
    }
}
