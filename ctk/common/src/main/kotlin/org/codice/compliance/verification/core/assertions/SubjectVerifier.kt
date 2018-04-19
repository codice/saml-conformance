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
package org.codice.compliance.verification.core.assertions

import org.codice.compliance.SAMLCore_2_4_1_2_a
import org.codice.compliance.attributeNode
import org.codice.compliance.recursiveChildren
import org.codice.compliance.verification.core.CommonDataTypeVerifier
import org.codice.compliance.verification.core.CoreVerifier.Companion.validateTimeWindow
import org.w3c.dom.Node

internal class SubjectVerifier(val node: Node) {

    /** 2.4 Subjects */
    fun verify() {
        verifySubjectConfirmation()
        verifySubjectConfirmationData()
    }

    /** 2.4.1.1 Element <SubjectConfirmation> */
    private fun verifySubjectConfirmation() {
        node.recursiveChildren("SubjectConfirmation")
                .forEach {
                    CommonDataTypeVerifier
                            .verifyUriValues(it.attributeNode("Method"))
                }
    }

    /** 2.4.1.2 Element <SubjectConfirmationData> */
    private fun verifySubjectConfirmationData() {
        node.recursiveChildren("SubjectConfirmationData").forEach {
            validateTimeWindow(it, SAMLCore_2_4_1_2_a)

            it.attributeNode("Recipient")?.let {
                CommonDataTypeVerifier.verifyUriValues(it)
            }

            it.attributeNode("Address")?.let {
                CommonDataTypeVerifier.verifyStringValues(it)
            }
        }
    }
}
