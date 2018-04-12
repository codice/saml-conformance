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

import org.apache.commons.lang3.StringUtils
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_1_3_1_a
import org.codice.compliance.SAMLCore_1_3_2_a
import org.codice.compliance.SAMLCore_1_3_3
import org.codice.compliance.SAMLCore_1_3_4
import org.codice.compliance.SAMLSpecRefMessage
import org.codice.compliance.XMLDatatypesSchema_3_2_7
import org.codice.compliance.XMLDatatypesSchema_3_2_7_1_a
import org.codice.compliance.XMLDatatypesSchema_3_2_7_1_b
import org.codice.compliance.XMLDatatypesSchema_3_2_7_1_c
import org.codice.compliance.utils.TestCommon.Companion.XSI
import org.w3c.dom.Node
import java.net.URI
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException

class CommonDataTypeVerifier {
    companion object {
        private const val FOUR_DIGIT_YEAR_LEN = 4
        private const val NO_HYPHEN_MESSAGE = "No hyphen was found in the date value of"

        var ids = mutableListOf<String>()

        /** 1.3 Common Data Types **/
        fun verifyCommonDataType(samlDom: Node) {
            ids = mutableListOf()

            for (i in samlDom.childNodes.length - 1 downTo 0) {
                val child = samlDom.childNodes.item(i)
                val typeAttribute = child.attributes?.getNamedItemNS(XSI, "type")
                if (typeAttribute?.textContent?.contains("string") == true)
                    verifyStringValues(child, null)
                if (typeAttribute?.textContent?.contains("anyURI") == true)
                    verifyUriValues(child, null)
                if (typeAttribute?.textContent?.contains("dateTime") == true)
                    verifyTimeValues(child, null)
                if (typeAttribute?.textContent?.contains("ID") == true)
                    verifyIdValues(child, null)

                if (child.hasChildNodes())
                    verifyCommonDataType(child)
            }
        }

        /** 1.3.1 String Values **/
        @Suppress("StringLiteralDuplication")
        fun verifyStringValues(node: Node, errorCode: SAMLSpecRefMessage?) {
            if (StringUtils.isBlank(node.textContent)) {
                if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_1_a,
                        message = "The String value of ${node.textContent} is invalid.")
                else throw SAMLComplianceException.create(SAMLCore_1_3_1_a,
                        message = "The String value of ${node.textContent} is invalid.")
            }
        }

        /** 1.3.2 URI Values **/
        fun verifyUriValues(node: Node, errorCode: SAMLSpecRefMessage?) {
            if (StringUtils.isBlank(node.textContent)
                    && !URI.create(node.textContent).isAbsolute) {
                if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_2_a,
                        message = "The URI value of ${node.textContent} is invalid.")
                else throw SAMLComplianceException.create(SAMLCore_1_3_2_a,
                        message = "The URI value of ${node.textContent} is invalid.")
            }
        }

        /** 1.3.4 ID and ID Reference Values **/
        fun verifyIdValues(node: Node, errorCode: SAMLSpecRefMessage?) {
            if (ids.contains(node.textContent)) {
                if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_4,
                        message = "The ID value of ${node.textContent} is not unique.")
                else throw SAMLComplianceException.create(SAMLCore_1_3_4,
                        message = "The ID value of ${node.textContent} is not unique.")
            } else ids.add(node.textContent)
        }

        /** 1.3.3 Time Values **/
        fun verifyTimeValues(node: Node, errorCode: SAMLSpecRefMessage?) {
            val dateTime = node.textContent
            val (year, restOfDateTime) = splitByYear(dateTime, errorCode)
            verifyYear(year, errorCode)
            verifyRestOfDateTime(restOfDateTime, errorCode)
        }

        /** verifyTimeValues helpers **/

        private data class SplitString(val year: String, val restOfDateTime: String)

        private fun splitByYear(dateTime: String, errorCode: SAMLSpecRefMessage?): SplitString {
            var hyphenIndex = dateTime.indexOf('-')

            if (hyphenIndex == -1) {
                if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_3,
                        XMLDatatypesSchema_3_2_7,
                        message = "$NO_HYPHEN_MESSAGE $dateTime.")
                else throw SAMLComplianceException.create(SAMLCore_1_3_3,
                        XMLDatatypesSchema_3_2_7,
                        message = "$NO_HYPHEN_MESSAGE $dateTime.")
            }

            // if year is negative, find the next '-'
            if (hyphenIndex == 0)
                hyphenIndex = dateTime.indexOf('-', hyphenIndex)

            if (hyphenIndex == -1) {
                if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_3,
                        XMLDatatypesSchema_3_2_7,
                        message = "$NO_HYPHEN_MESSAGE $dateTime.")
                else throw SAMLComplianceException.create(SAMLCore_1_3_3, XMLDatatypesSchema_3_2_7,
                        message = "$NO_HYPHEN_MESSAGE $dateTime.")
            }
            return SplitString(dateTime.substring(0, hyphenIndex), dateTime.substring(
                    hyphenIndex + 1))
        }

        // https://www.w3.org/TR/xmlschema-2/#dateTime
        @Suppress("SpreadOperator"
                /* Judicious use of spread operator to reduce cognitive complexity */)
        private fun verifyYear(year: String, errorCode: SAMLSpecRefMessage?) {
            // remove the negative sign to make verification easier
            val strippedYear: String = if (year.indexOf('-') == 0) year.substring(1)
            else year

            val codes = if (errorCode == null) emptyArray()
            else arrayOf(errorCode)

            // check if year is an integer && "a plus sign is not permitted"
            if (!strippedYear.matches("""\d+""".toRegex())) {
                throw SAMLComplianceException.create(*codes,
                        SAMLCore_1_3_3,
                        XMLDatatypesSchema_3_2_7_1_c,
                        message = "A '+' was found.")
            }

            // "if more than four digits, leading zeros are prohibited"
            if (strippedYear.length > FOUR_DIGIT_YEAR_LEN && strippedYear.startsWith('0')) {
                throw SAMLComplianceException.create(*codes,
                        SAMLCore_1_3_3,
                        XMLDatatypesSchema_3_2_7_1_a,
                        message = "The year value of $strippedYear is invalid.")
            }

            // "'0000' is prohibited"
            if (strippedYear == "0000") {
                throw SAMLComplianceException.create(*codes,
                        SAMLCore_1_3_3,
                        XMLDatatypesSchema_3_2_7_1_b,
                        message = "The year value of $strippedYear is invalid.")
            }
        }

        // TODO allow an unlimited amount of fractional seconds as stated in the XML Datatypes
        // Schema 3.2.7
        // TODO "SAML system entities SHOULD NOT rely on time resolution finer than milliseconds"
        // Core.1.3.3 helper for verifyTimeValues
        private fun verifyRestOfDateTime(restOfDateTime: String, errorCode: SAMLSpecRefMessage?) {
            val format = DateTimeFormatter.ofPattern(
                    "MM'-'dd'T'HH':'mm':'ss['.'SSS]['Z']")

            try {
                format.parse(restOfDateTime)
            } catch (e: DateTimeParseException) {
                if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_3,
                        XMLDatatypesSchema_3_2_7,
                        message = "The date value of $restOfDateTime is incorrectly formatted.",
                        cause = e)
                else throw SAMLComplianceException.create(SAMLCore_1_3_3,
                        XMLDatatypesSchema_3_2_7,
                        message = "The date value of $restOfDateTime is incorrectly formatted.",
                        cause = e)
            }
        }
    }
}
