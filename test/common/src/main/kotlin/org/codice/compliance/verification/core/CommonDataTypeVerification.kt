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
import org.w3c.dom.Node
import java.net.URI
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException

var ids = mutableListOf<String>()

/**
 * Verify common data types against the core specification
 *
 * 1.3 Common Data Types
 */
fun verifyCommonDataType(samlDom: Node) {
    ids = mutableListOf()
    var i = samlDom.childNodes.length - 1

    while (i >= 0) {
        val child = samlDom.childNodes.item(i)
        val typeAttribute = child.attributes?.getNamedItemNS("http://www.w3.org/2001/XMLSchema-instance", "type")
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
        i -= 1
    }
}

/**
 * Verify values of type string
 *
 * 1.3.1 String Values
 */
fun verifyStringValues(node: Node, errorCode: String?) {
    if (StringUtils.isBlank(node.textContent)) {
        if (errorCode != null) throw SAMLComplianceException.create("SAMLCore.1.3.4_b", errorCode)
        else throw SAMLComplianceException.create("SAMLCore.1.3.4_b")
    }
}

/**
 * Verify values of type anyURI
 *
 * 1.3.2 URI Values
 */
fun verifyUriValues(node: Node, errorCode: String?) {
    // todo - make sure uri absolute check is correct
    if (StringUtils.isBlank(node.textContent)
            && !URI.create(node.textContent).isAbsolute) {
        if (errorCode != null) throw SAMLComplianceException.create("SAMLCore.1.3.4_b", errorCode)
        else throw SAMLComplianceException.create("SAMLCore.1.3.4_b")
    }
}

/**
 * Verify values of type ID
 *
 * 1.3.4 ID and ID Reference Values
 */
fun verifyIdValues(node: Node, errorCode: String?) {
    if (ids.contains(node.textContent)) {
        if (errorCode != null) throw SAMLComplianceException.create("SAMLCore.1.3.4_b", errorCode)
        else throw SAMLComplianceException.create("SAMLCore.1.3.4_b")
    } else ids.add(node.textContent)
}

/**
 * Verify values of type dateTime
 *
 * 1.3.3 Time Values
 */
fun verifyTimeValues(node: Node, errorCode: String?) {
    val dateTime = node.textContent
    val (year, restOfDateTime) = splitByYear(dateTime, errorCode)
    verifyYear(year, errorCode)
    verifyRestOfDateTime(restOfDateTime, errorCode)
}

/** verifyTimeValues helpers **/

private data class SplitString(val year: String, val restOfDateTime: String)

private fun splitByYear(dateTime: String, errorCode: String?): SplitString {
    var hyphenIndex = dateTime.indexOf('-')

    if (hyphenIndex == -1) {
        if (errorCode != null) throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7", "SAMLCore.1.3.3_a", errorCode)
        else throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7", "SAMLCore.1.3.3_a")
    }

    // if year is negative, find the next '-'
    if (hyphenIndex == 0)
        hyphenIndex = dateTime.indexOf('-', hyphenIndex)

    if (hyphenIndex == -1) {
        if (errorCode != null) throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7", "SAMLCore.1.3.3_a", errorCode)
        else throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7", "SAMLCore.1.3.3_a")
    }
    return SplitString(dateTime.substring(0, hyphenIndex), dateTime.substring(hyphenIndex + 1))
}

private fun verifyYear(year: String, errorCode: String?) {
    // remove the negative sign to make verification easier
    val strippedYear: String = if (year.indexOf('-') == 0) year.substring(1) else year

    // check if year is an integer && https://www.w3.org/TR/xmlschema-2/#dateTime "a plus sign is not permited"
    if (!strippedYear.matches(Regex("\\d+"))) {
        if (errorCode != null) throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7.1_a3", "SAMLCore.1.3.3_a", errorCode)
        else throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7.1_a3", "SAMLCore.1.3.3_a")
    }

    // https://www.w3.org/TR/xmlschema-2/#dateTime "if more than four digits, leading zeros are prohibited"
    if (strippedYear.length > 4 && strippedYear.startsWith('0')) {
        if (errorCode != null) throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7.1_a1", "SAMLCore.1.3.3_a", errorCode)
        else throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7.1_a1", "SAMLCore.1.3.3_a")
    }

    // https://www.w3.org/TR/xmlschema-2/#dateTime "'0000' is prohibited"
    if (strippedYear == "0000") {
        if (errorCode != null) throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7.1_a2", "SAMLCore.1.3.3_a", errorCode)
        else throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7.1_a2", "SAMLCore.1.3.3_a")
    }
}

// todo allow an unlimited amount of fractional seconds as stated in the XML Datatypes Schema 3.2.7
// todo "SAML system entities SHOULD NOT rely on time resolution finer than milliseconds" Core.1.3.3
// helper for verifyTimeValues
private fun verifyRestOfDateTime(restOfDateTime: String, errorCode: String?) {
    val format = DateTimeFormatter.ofPattern("MM'-'dd'T'HH':'mm':'ss['.'SSS]['Z']")

    try {
        format.parse(restOfDateTime)
    } catch (e: DateTimeParseException) {
        if (errorCode != null) throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7", "SAMLCore.1.3.3_a", errorCode)
        else throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7", "SAMLCore.1.3.3_a")
    }
}