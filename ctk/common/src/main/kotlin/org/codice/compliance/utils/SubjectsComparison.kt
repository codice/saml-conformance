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
package org.codice.compliance.utils

import org.codice.compliance.children
import org.w3c.dom.Node

class SubjectsComparison(private val subject1: Node, private val subject2: Node) {
    /**
     * Compares two subjects according to the Core document section 3.3.4
     */
    fun subjectsMatch(): Boolean {
        return idMatch() && subjectConfirmationMatch()
    }

    private fun subjectConfirmationMatch(): Boolean {
        val subjectConfirmation1 = subject1.children("SubjectConfirmation")
        val subjectConfirmation2 = subject2.children("SubjectConfirmation")

        if (subjectConfirmation1.isNotEmpty() && subjectConfirmation2.isNotEmpty()) {

            subjectConfirmation1.forEachIndexed { _, sc1 ->
                subjectConfirmation2.forEachIndexed { _, sc2 ->
                    if (sc1.attributes.getNamedItem("Method") ==
                            sc2.attributes.getNamedItem("Method"))
                        return true
                }
            }
        }
        return false
    }

    @SuppressWarnings("ReturnCount")
    private fun idMatch(): Boolean {
        val subject1Name = subject1.localName
        val subject2Name = subject2.localName
        if (subject1Name == "EncryptedID") {
            // decrypt
        }

        if (subject2Name == "EncryptedID") {
            // decrypt
        }

        if (subject1Name != subject2Name)
            return baseIdsMatch()

        when (subject1Name) {
            "BaseID" -> return baseIdsMatch()
            "NameID" -> return nameIdsMatch()
        }
        return false
    }

    private fun baseIdsMatch(): Boolean {
        return compareAttributes("NameQualifier")
                && compareAttributes("SPNameQualifier")
    }

    private fun nameIdsMatch(): Boolean {
        return baseIdsMatch()
                && compareAttributes("Format")
                && compareAttributes("SPProvidedID")
    }

    private fun compareAttributes(attribute: String): Boolean {
        return subject1.attributes.getNamedItem(attribute).textContent ==
                subject2.attributes.getNamedItem(attribute).textContent
    }
}
