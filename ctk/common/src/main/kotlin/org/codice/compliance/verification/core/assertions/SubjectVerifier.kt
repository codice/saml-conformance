/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.core.assertions

import org.codice.compliance.SAMLCore_2_4_1_2_a
import org.codice.compliance.attributeNode
import org.codice.compliance.recursiveChildren
import org.codice.compliance.Section.CORE_2_4
import org.codice.compliance.utils.METHOD
import org.codice.compliance.utils.SUBJECT_CONFIRMATION
import org.codice.compliance.utils.SUBJECT_CONFIRMATION_DATA
import org.codice.compliance.verification.core.CommonDataTypeVerifier
import org.codice.compliance.verification.core.CoreVerifier.Companion.validateTimeWindow
import org.w3c.dom.Node

internal class SubjectVerifier(val node: Node) {

    /** 2.4 Subjects */
    fun verify() {
        CORE_2_4.start()
        verifySubjectConfirmation()
        verifySubjectConfirmationData()
    }

    /** 2.4.1.1 Element <SubjectConfirmation> */
    private fun verifySubjectConfirmation() {
        node.recursiveChildren(SUBJECT_CONFIRMATION)
                .forEach {
                    CommonDataTypeVerifier
                            .verifyUriValue(it.attributeNode(METHOD))
                }
    }

    /** 2.4.1.2 Element <SubjectConfirmationData> */
    private fun verifySubjectConfirmationData() {
        node.recursiveChildren(SUBJECT_CONFIRMATION_DATA).forEach {
            validateTimeWindow(it, SAMLCore_2_4_1_2_a)

            it.attributeNode("Recipient")?.let {
                CommonDataTypeVerifier.verifyUriValue(it)
            }

            it.attributeNode("Address")?.let {
                CommonDataTypeVerifier.verifyStringValue(it)
            }
        }
    }
}
