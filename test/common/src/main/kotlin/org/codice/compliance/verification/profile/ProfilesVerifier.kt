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
package org.codice.compliance.verification.profile

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLSpecRefMessage.SAMLProfiles_3_1_a
import org.codice.compliance.SAMLSpecRefMessage.SAMLProfiles_3_1_b
import org.codice.compliance.SAMLSpecRefMessage.SAMLProfiles_3_1_c
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon.Companion.HOLDER_OF_KEY_URI
import org.codice.compliance.utils.TestCommon.Companion.SAML_NAMESPACE
import org.codice.compliance.utils.TestCommon.Companion.XSI
import org.w3c.dom.Node

class ProfilesVerifier(private val node: Node) {
    /**
     * Verify response against the Profiles Spec document
     */
    fun verify() {
        verifyHolderOfKey()
    }

    private fun verifyHolderOfKey() {
        val subjectConfirmationDataList = node.allChildren("SubjectConfirmation")
                .filter { it.attributes.getNamedItem("Method").textContent == HOLDER_OF_KEY_URI }
                .flatMap { it.children("SubjectConfirmationData") }

        subjectConfirmationDataList.forEach {
            val type = it.attributes.getNamedItemNS(XSI, "type")
            if (type != null && !type.textContent.contains("KeyInfoConfirmationDataType"))
                throw SAMLComplianceException.createWithPropertyNotEqualMessage(SAMLProfiles_3_1_b,
                        "type", type.textContent, "KeyInfoConfirmationDataType")

            if (type.firstChild.namespaceURI != SAML_NAMESPACE)
                throw SAMLComplianceException.createWithPropertyNotEqualMessage(SAMLProfiles_3_1_b,
                        "the namespace prefix", type.firstChild.namespaceURI, SAML_NAMESPACE)

            val keyInfos = it.children("KeyInfo")
            if (keyInfos.isEmpty())
                throw SAMLComplianceException.create(SAMLProfiles_3_1_a,
                        message = "<ds:KeyInfo> not found within the <SubjectConfirmationData> element.")

            keyInfos.forEach {
                if (it.childNodes.length > 1)
                    throw SAMLComplianceException.create(SAMLProfiles_3_1_c,
                            message = "<ds:KeyInfo> must not have multiple values.")
            }
        }
    }
}
