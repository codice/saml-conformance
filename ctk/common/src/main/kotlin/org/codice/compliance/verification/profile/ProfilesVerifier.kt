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
import org.codice.compliance.SAMLProfiles_3_1_a
import org.codice.compliance.SAMLProfiles_3_1_b
import org.codice.compliance.SAMLProfiles_3_1_c
import org.codice.compliance.SAMLProfiles_4_1_4_2_l
import org.codice.compliance.SAMLSpecRefMessage
import org.codice.compliance.attributeNodeNS
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon.Companion.ASSERTION
import org.codice.compliance.utils.TestCommon.Companion.HOLDER_OF_KEY_URI
import org.codice.compliance.utils.TestCommon.Companion.SAML_NAMESPACE
import org.codice.compliance.utils.TestCommon.Companion.SUBJECT_CONFIRMATION
import org.codice.compliance.utils.TestCommon.Companion.XSI
import org.w3c.dom.Node

class ProfilesVerifier(private val node: Node) {

    /**
     * Verify Error Response against the Profiles document.
     * This should be called explicitly if an error is expected.
     */
    fun verifyErrorResponseAssertion(samlErrorCode: SAMLSpecRefMessage? = null) {
        if (node.recursiveChildren(ASSERTION).isNotEmpty()) {
            val exceptions: Array<SAMLSpecRefMessage> =
                    if (samlErrorCode != null)
                        arrayOf(samlErrorCode, SAMLProfiles_4_1_4_2_l)
                    else
                        arrayOf(SAMLProfiles_4_1_4_2_l)

            @Suppress("SpreadOperator")
            throw SAMLComplianceException.create(*exceptions,
                    message = "A Response must not have an assertion if it's an error response.",
                    node = node)
        }
    }

    /**
     * Verify response against the Profiles Spec document
     */
    fun verify() {
        verifyHolderOfKey()
    }

    /**
     * 3.1 Holder of Key
     */
    private fun verifyHolderOfKey() {
        val holderOfKeyList = node.recursiveChildren(SUBJECT_CONFIRMATION)
                .filter { it.attributeText("Method") == HOLDER_OF_KEY_URI }

        if (holderOfKeyList.isEmpty()) return

        val holderOfKeyDataList = holderOfKeyList
                .flatMap { it.children("SubjectConfirmationData") }

        if (holderOfKeyDataList.isEmpty())
            throw SAMLComplianceException.create(SAMLProfiles_3_1_a,
                message = "<SubjectConfirmationData> not found within Holder of Key " +
                        "<SubjectConfirmation>",
                node = node)

        holderOfKeyDataList.forEach {
            val type = it.attributeNodeNS(XSI, "type")
            if (type != null && !type.textContent.contains("KeyInfoConfirmationDataType"))
                throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_3_1_b,
                        property = "type",
                        actual = type.textContent,
                        expected = "KeyInfoConfirmationDataType",
                        node = node)

            if (type?.firstChild?.namespaceURI != SAML_NAMESPACE)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_3_1_b,
                        property = "the namespace prefix",
                        actual = type?.firstChild?.namespaceURI,
                        expected = SAML_NAMESPACE,
                        node = node)

            val keyInfos = it.children("KeyInfo")
            if (keyInfos.isEmpty())
                throw SAMLComplianceException.create(SAMLProfiles_3_1_a,
                        message = "<ds:KeyInfo> not found within the <SubjectConfirmationData> " +
                                "element.",
                        node = node)

            keyInfos.forEach {
                if (it.children("KeyValue").size > 1)
                    throw SAMLComplianceException.create(SAMLProfiles_3_1_c,
                            message = "<ds:KeyInfo> must not have multiple values.",
                            node = node)
            }
        }
    }
}
