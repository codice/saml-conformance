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
package org.codice.compliance.verification.core.internal

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_2_4_1_2_c
import org.codice.compliance.SAMLCore_2_4_1_3
import org.codice.compliance.SAMLCore_2_5_1_2
import org.codice.compliance.XMLSignature_4_5
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon
import org.w3c.dom.Node
import java.time.Instant

internal class SubjectVerifier(val node: Node) {

    fun verify() {
        verifySubjectConfirmation()
        verifySubjectConfirmationData()
    }

    /**
     * Verify subject elements against the Core Spec
     * 2.4.1.1 Element <SubjectConfirmation>
     */
    private fun verifySubjectConfirmation() {
        if (node.allChildren("SubjectConfirmation")
                        .any { it.attributes.getNamedItem("Method") == null })
            throw SAMLComplianceException
                    .createWithXmlPropertyReqMessage("SAMLCore.2.4.1.1",
                            "Method",
                            "SubjectConfirmation",
                            node = node)
    }

    /**
     * 2.4.1.2 Element <SubjectConfirmationData>
     * 2.4.1.3 Complex Type KeyInfoConfirmationDataType
     */
    private fun verifySubjectConfirmationData() {
        node.allChildren("SubjectConfirmationData").forEach {
            val notBefore = it.attributes.getNamedItem("NotBefore")
            val notOnOrAfter = it.attributes.getNamedItem("NotOnOrAfter")
            if (notBefore != null
                    && notOnOrAfter != null) {
                val notBeforeValue = Instant.parse(notBefore.textContent)
                val notOnOrAfterValue = Instant.parse(notOnOrAfter.textContent)
                if (notBeforeValue.isAfter(notOnOrAfterValue))
                    throw SAMLComplianceException.create(SAMLCore_2_5_1_2,
                            message = "NotBefore element with value $notBeforeValue is not less" +
                                    "than NotOnOrAfter element with value $notOnOrAfterValue.",
                            node = node)
            }

            // KeyInfoConfirmationDataType
            if (it.attributes
                            ?.getNamedItemNS(TestCommon.XSI, "type")
                            ?.textContent?.contains("KeyInfoConfirmationDataType") == true
                    && it.children("KeyInfo").any { it.children("KeyValue").size > 1 })
                throw SAMLComplianceException.create(SAMLCore_2_4_1_3, XMLSignature_4_5,
                        message = "Multiple Keys found within the KeyInfo element.",
                        node = node)

            for (i in it.attributes.length - 1 downTo 0) {
                val attribute = it.attributes.item(i)
                if (isNullOrSamlNamespace(attribute) && isUnknownSamlAttribute(attribute)) {
                    throw SAMLComplianceException.create(SAMLCore_2_4_1_2_c,
                            message = "An unknown attribute element was found on the " +
                                    "<SubjectConfirmationData> node element.",
                            node = attribute)
                }
            }
        }
    }

    private fun isNullOrSamlNamespace(attribute: Node): Boolean {
        return with(attribute) {
            namespaceURI == null || namespaceURI == TestCommon.SAML_NAMESPACE
        }
    }

    private fun isUnknownSamlAttribute(attribute: Node): Boolean {
        return !listOf("NotBefore", "NotOnOrAfter", "Recipient", "InResponseTo",
                "Address").contains(
                attribute.localName)
    }
}
