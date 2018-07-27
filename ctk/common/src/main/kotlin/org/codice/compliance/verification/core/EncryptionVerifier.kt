/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
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
import org.codice.compliance.utils.ELEMENT
import org.codice.compliance.utils.TYPE
import org.codice.compliance.utils.XMLDecrypter
import org.codice.compliance.utils.XMLDecrypter.Companion.XMLDecryptorException
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
     * @param encElements A list of encrypted nodes to verify and decrypt
     */
    fun verifyAndDecryptElements(encElements: List<Node>) {
        encElements.forEach {
            verifyAndDecryptElement(it)
        }
    }

    private fun verifyAndDecryptElement(element: Node) {
        verifyEncryptedElement(element)

        try {
            XMLDecrypter.decryptAndReplaceNode(element)
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
