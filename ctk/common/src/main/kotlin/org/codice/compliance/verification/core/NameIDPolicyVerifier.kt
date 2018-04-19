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

import org.apache.wss4j.common.saml.builder.SAML2Constants
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_4_1_1a
import org.codice.compliance.SAMLCore_3_4_1_1b
import org.codice.compliance.SAMLCore_3_4_1_1c
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.ASSERTION
import org.codice.compliance.utils.TestCommon.Companion.NAMEID_ENCRYPTED
import org.opensaml.saml.saml2.core.NameIDPolicy
import org.w3c.dom.Node

class NameIDPolicyVerifier(private val response: Node, private val policy: NameIDPolicy) {

    /** 3.4.1.1 Element <NameIDPolicy> **/
    internal fun verify() {
        response
                .recursiveChildren(ASSERTION)
                .flatMap { it.children("Subject") }
                .flatMap { it.children("NameID") }
                .forEach {
                    when (policy.format) {
                        SAML2Constants.ATTRNAME_FORMAT_UNSPECIFIED, NAMEID_ENCRYPTED -> {
                        }
                        else -> {
                            verifyFormatsMatch(it)
                        }
                    }

                    verifySPNameQualifiersMatch(it)
                }
    }

    private fun verifySPNameQualifiersMatch(nameId: Node) {
        nameId.attributeText("SPNameQualifier")?.let { spnq ->
            if (spnq != policy.spNameQualifier) {
                throw SAMLComplianceException.create(SAMLCore_3_4_1_1c,
                        message = "A NameID element was found with a SPNameQualifier " +
                                "attribute value of $spnq instead of " +
                                "${policy.spNameQualifier}.",
                        node = nameId)
            }
        }
    }

    private fun verifyFormatsMatch(nameId: Node) {
        nameId.attributeText("Format").let { idFormat ->
            if (!idFormat.equals(policy.format)) {
                throw SAMLComplianceException.create(SAMLCore_3_4_1_1b,
                        message = "A NameID element was found with a Format attribute " +
                                "value of $idFormat instead of ${policy.format}.",
                        node = nameId)
            }
        }
    }

    internal fun verifyEncryptedIds() {
        if (policy.format == TestCommon.NAMEID_ENCRYPTED) {
            val subjects = response.recursiveChildren(ASSERTION)
                    .flatMap { it.children("Subject") }

            if (subjects.any { it.children("EncryptedID").isEmpty() }) {
                throw SAMLComplianceException.create(SAMLCore_3_4_1_1a,
                        message = "An Assertion element was found without an EncryptedID element" +
                                " in its Subject element.",
                        node = response)
            }

            if (subjects.any { it.children("NameID").isNotEmpty() }) {
                throw SAMLComplianceException.create(SAMLCore_3_4_1_1a,
                        message = "An Assertion element was found with a NameID element in " +
                                "its Subject element.",
                        node = response)
            }
        }
    }
}
