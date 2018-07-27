/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.profile.subject.confirmations

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_3_1_a
import org.codice.compliance.SAMLProfiles_3_1_b
import org.codice.compliance.SAMLProfiles_3_1_c
import org.codice.compliance.attributeNodeNS
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.ASSERTION
import org.codice.compliance.utils.ASSERTION_NAMESPACE
import org.codice.compliance.utils.HOLDER_OF_KEY_URI
import org.codice.compliance.utils.KEY_INFO_CONFIRMATION_DATA_TYPE
import org.codice.compliance.utils.METHOD
import org.codice.compliance.utils.SUBJECT_CONFIRMATION
import org.codice.compliance.utils.SUBJECT_CONFIRMATION_DATA
import org.codice.compliance.utils.XSI
import org.w3c.dom.Node

class HolderOfKeySubjectConfirmationVerifier(private val samlResponseDom: Node) {

    /** 3.1 Holder of Key */
    fun verify() {
        val holderOfKeyList = samlResponseDom.recursiveChildren(SUBJECT_CONFIRMATION)
            .filter { it.attributeText(METHOD) == HOLDER_OF_KEY_URI }

        if (holderOfKeyList.isEmpty()) return

        holderOfKeyList.forEach {
            val subjectConfirmationDataElements = it.children(SUBJECT_CONFIRMATION_DATA)

            if (subjectConfirmationDataElements.isEmpty())
                throw SAMLComplianceException.create(SAMLProfiles_3_1_a,
                    message = "<SubjectConfirmationData> not found within Holder of Key " +
                        "<SubjectConfirmation>",
                    node = samlResponseDom)

            subjectConfirmationDataElements.forEach { verifyHolderOfKeyData(it) }
        }
    }

    private fun verifyHolderOfKeyData(node: Node) {
        val type = node.attributeNodeNS(XSI, "type")
        if (type != null) {
            if (!type.textContent.contains(":"))
                throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_3_1_b,
                    property = "type",
                    actual = type.textContent,
                    expected = KEY_INFO_CONFIRMATION_DATA_TYPE,
                    node = node)

            val (namespace, value) = type.textContent.split(":")
            if (value != KEY_INFO_CONFIRMATION_DATA_TYPE)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_3_1_b,
                    property = "type",
                    actual = value,
                    expected = KEY_INFO_CONFIRMATION_DATA_TYPE,
                    node = node)

            // SSO Response must have at least one assertion with an assertion namespace
            val assertionNameSpacePrefix = samlResponseDom.children(ASSERTION)
                .first()
                .nodeName.split(":")
                .first()
            if (namespace != assertionNameSpacePrefix)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_3_1_b,
                    property = "namespace prefix",
                    actual = namespace,
                    expected = "$assertionNameSpacePrefix which maps to " +
                        ASSERTION_NAMESPACE,
                    node = node)
        }

        val keyInfos = node.children("KeyInfo")
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
