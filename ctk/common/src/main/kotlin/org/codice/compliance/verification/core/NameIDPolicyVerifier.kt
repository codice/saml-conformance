/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.core

import org.apache.wss4j.common.saml.builder.SAML2Constants
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_4_1_1_a
import org.codice.compliance.SAMLCore_3_4_1_1_b
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.report.Report
import org.codice.compliance.utils.ASSERTION
import org.codice.compliance.utils.ENCRYPTED_ID
import org.codice.compliance.utils.FORMAT
import org.codice.compliance.utils.SP_NAME_QUALIFIER
import org.codice.compliance.utils.SUBJECT
import org.opensaml.saml.saml2.core.NameIDPolicy
import org.w3c.dom.Node

class NameIDPolicyVerifier(private val samlResponseDom: Node, private val policy: NameIDPolicy) {
    private val policyFormat = policy.format

    /** 3.4.1.1 Element <NameIDPolicy> **/
    internal fun verify() {
        samlResponseDom
                .recursiveChildren(ASSERTION)
                .flatMap { it.children(SUBJECT) }
                .flatMap { it.children("NameID") }
                .forEach {
                    when (policyFormat) {
                        SAML2Constants.ATTRNAME_FORMAT_UNSPECIFIED, ENCRYPTED_ID -> {
                        }
                        else -> verifyFormatsMatch(it)
                    }
                    verifySPNameQualifiersMatch(it)
                }
    }

    private fun verifySPNameQualifiersMatch(nameId: Node) {
        nameId.attributeText(SP_NAME_QUALIFIER)?.let { spnq ->
            val spNameQualifier = policy.spNameQualifier
            if (spnq != spNameQualifier) {
                Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_3_4_1_1_b,
                        message = "A NameID element was found with a SPNameQualifier " +
                                "attribute value of $spnq instead of " +
                                "$spNameQualifier.",
                        node = nameId))
            }
        }
    }

    private fun verifyFormatsMatch(nameId: Node) {
        nameId.attributeText(FORMAT).let { idFormat ->
            if (idFormat != policyFormat) {
                Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_3_4_1_1_b,
                        message = "A NameID element was found with a Format attribute " +
                                "value of $idFormat instead of $policyFormat.",
                        node = nameId))
            }
        }
    }

    internal fun verifyEncryptedIds() {
        if (policyFormat == ENCRYPTED_ID) {
            val subjects = samlResponseDom.recursiveChildren(ASSERTION)
                    .flatMap { it.children(SUBJECT) }

            if (subjects.any { it.children("EncryptedID").isEmpty() }) {
                Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_3_4_1_1_a,
                        message = "An Assertion element was found without an EncryptedID element" +
                                " in its Subject element.",
                        node = samlResponseDom))
            }

            if (subjects.any { it.children("NameID").isNotEmpty() }) {
                Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_3_4_1_1_a,
                        message = "An Assertion element was found with a NameID element in " +
                                "its Subject element.",
                        node = samlResponseDom))
            }
        }
    }
}
