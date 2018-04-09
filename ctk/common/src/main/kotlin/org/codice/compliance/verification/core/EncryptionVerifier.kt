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
import org.codice.compliance.SAMLCore_2_7_3_2_a
import org.codice.compliance.SAMLCore_6_1_a
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.XMLDecryptor
import org.codice.compliance.utils.XMLDecryptor.Companion.XMLDecryptorException
import org.w3c.dom.Node

class EncryptionVerifier {

    /**
     * This function has 4 responsibilities:
     * <ol>
     * <li>Locating all of the encrypted elements within the given response</li>
     * <li>Running verifications on the elements</li>
     * <li>Decrypting the elements</li>
     * <li>Replacing the encrypted elements with their unencrypted values</li>
     * </ol>
     *
     * @param response The response node to verify and decrypt
     */
    fun verifyAndDecrypt(response: Node) {
        val encryptedNodeList = response.allChildren("EncryptedAssertion")
                .union(response.allChildren("EncryptedAttribute"))
                .union(response.allChildren("EncryptedId"))

        encryptedNodeList.forEach({
            verifyEncryptedElement(it)

            try {
                XMLDecryptor.decryptAndReplaceNode(it)
            } catch (e: XMLDecryptorException) {
                throw SAMLComplianceException.create(
                        SAMLCore_6_1_a,
                        message = e.message,
                        cause = e.cause,
                        node = response)
            }
        })
    }

    private fun verifyEncryptedElement(encryptedElement: Node) {
        if (encryptedElement.children("EncryptedData")
                        .first() // guaranteed to have an EncryptedData child by schema validation
                        .attributes.getNamedItem("Type")
                        .textContent != TestCommon.ELEMENT)
            throw SAMLComplianceException.createWithPropertyMessage(
                    SAMLCore_2_7_3_2_a,
                    property = TestCommon.TYPE,
                    actual = encryptedElement.attributes.getNamedItem(TestCommon.TYPE).textContent,
                    expected = TestCommon.ELEMENT,
                    node = encryptedElement)
    }
}
