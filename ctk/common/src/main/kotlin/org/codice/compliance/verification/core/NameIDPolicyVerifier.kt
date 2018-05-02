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
import org.codice.compliance.SAMLCore_3_4_1_1_a
import org.codice.compliance.SAMLCore_3_4_1_1_b
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon.Companion.ASSERTION
import org.codice.compliance.utils.TestCommon.Companion.FORMAT
import org.codice.compliance.utils.TestCommon.Companion.NAMEID_ENCRYPTED
import org.codice.compliance.utils.TestCommon.Companion.SUBJECT
import org.opensaml.saml.saml2.core.NameIDPolicy
import org.w3c.dom.Node

class NameIDPolicyVerifier(private val samlResponseDom: Node, private val policy: NameIDPolicy) {
    val policyFormat = policy.format

    /** 3.4.1.1 Element <NameIDPolicy> **/
    internal fun verify() {
        samlResponseDom
                .recursiveChildren(ASSERTION)
                .flatMap { it.children(SUBJECT) }
                .flatMap { it.children("NameID") }
                .forEach {
                    when (policyFormat) {
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
            val spNameQualifier = policy.spNameQualifier
            if (spnq != spNameQualifier) {
                throw SAMLComplianceException.create(SAMLCore_3_4_1_1_b,
                        message = "A NameID element was found with a SPNameQualifier " +
                                "attribute value of $spnq instead of " +
                                "$spNameQualifier.",
                        node = nameId)
            }
        }
    }

    private fun verifyFormatsMatch(nameId: Node) {
        nameId.attributeText(FORMAT).let { idFormat ->
            if (idFormat != policyFormat) {
                throw SAMLComplianceException.create(SAMLCore_3_4_1_1_b,
                        message = "A NameID element was found with a Format attribute " +
                                "value of $idFormat instead of $policyFormat.",
                        node = nameId)
            }
        }
    }

    internal fun verifyEncryptedIds() {
        if (policyFormat == NAMEID_ENCRYPTED) {
            val subjects = samlResponseDom.recursiveChildren(ASSERTION)
                    .flatMap { it.children(SUBJECT) }

            if (subjects.any { it.children("EncryptedID").isEmpty() }) {
                throw SAMLComplianceException.create(SAMLCore_3_4_1_1_a,
                        message = "An Assertion element was found without an EncryptedID element" +
                                " in its Subject element.",
                        node = samlResponseDom)
            }

            if (subjects.any { it.children("NameID").isNotEmpty() }) {
                throw SAMLComplianceException.create(SAMLCore_3_4_1_1_a,
                        message = "An Assertion element was found with a NameID element in " +
                                "its Subject element.",
                        node = samlResponseDom)
            }
        }
    }
}
