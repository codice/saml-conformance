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
import org.codice.compliance.SAMLCore_2_3_4_a
import org.codice.compliance.SAMLCore_2_7_3_2_a
import org.codice.compliance.SAMLCore_6_1_a
import org.codice.compliance.SAMLCore_6_1_b
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon.Companion.ELEMENT
import org.codice.compliance.utils.TestCommon.Companion.TYPE
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
     * @param encElements A list of encrypted nodes to decodeAndVerify and decrypt
     */
    fun verifyAndDecryptElements(encElements: List<Node>) {
        encElements.forEach {
            verifyAndDecryptElement(it)
        }
    }

    private fun verifyAndDecryptElement(element: Node) {
        verifyEncryptedElement(element)

        try {
            XMLDecryptor.decryptAndReplaceNode(element)
        } catch (e: XMLDecryptorException) {
            throw SAMLComplianceException.create(
                    SAMLCore_6_1_a,
                    message = e.message,
                    cause = e.cause,
                    node = element)
        }
    }

    private fun verifyEncryptedElement(encryptedElement: Node) {
        if (encryptedElement.children("EncryptedData")
                        .first() // guaranteed to have an EncryptedData child by schema validation
                        .attributeText(TYPE) != ELEMENT)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_6_1_b,
                    when (encryptedElement.localName) {
                        "EncryptedID" -> SAMLCore_2_2_4_a
                        "EncryptedAssertion" -> SAMLCore_2_3_4_a
                        "EncryptedAttribute" -> SAMLCore_2_7_3_2_a
                        else -> throw UnknownError("Unknown ${encryptedElement.localName} type.")
                    },
                    property = TYPE,
                    actual = encryptedElement.attributeText(TYPE),
                    expected = ELEMENT,
                    node = encryptedElement)
    }
}
