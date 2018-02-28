package org.codice.compliance.core

import org.apache.commons.lang3.StringUtils
import org.codice.compliance.SAMLComplianceException
import org.w3c.dom.Node
import java.net.URI
import java.time.format.DateTimeFormatter
import java.time.format.DateTimeParseException

val ids = mutableListOf<String>()

/**
 * Verify common data types against the core specification
 *
 * 1.3 Common Data Types
 */
fun verifyCommonDataType(response: Node) {
    var i = response.childNodes.length - 1

    while (i >= 0) {
        val child = response.childNodes.item(i)
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

// helper for verifyTimeValues
data class SplitString(val year: String, val restOfDateTime: String)
fun splitByYear(dateTime: String, errorCode: String?):  SplitString {
    var hyphenIndex = dateTime.indexOf('-')

    if (hyphenIndex == -1) {
        if (errorCode != null) throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7", "SAMLCore.1.3.3_a", errorCode)
        else throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7", "SAMLCore.1.3.3_a")
    }

    // if year is negative, find the next '-'
    if (hyphenIndex == 0) {
        hyphenIndex = dateTime.indexOf('-', hyphenIndex)
    }

    if (hyphenIndex == -1) {
        if (errorCode != null) throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7", "SAMLCore.1.3.3_a", errorCode)
        else throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7", "SAMLCore.1.3.3_a")
    }

    val year = dateTime.substring(0, hyphenIndex)
    val restOfDateTime = dateTime.substring(hyphenIndex + 1)

    return SplitString(year, restOfDateTime)
}

// helper for verifyTimeValues
fun verifyYear(year: String, errorCode: String?) {
    // remove the negative sign to make verification easier
    val strippedYear: String
    if (year.indexOf('-') == 0) {
        strippedYear = year.substring(1)
    } else {
        strippedYear = year
    }

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
fun verifyRestOfDateTime(restOfDateTime: String, errorCode: String?) {
    val format = DateTimeFormatter.ofPattern("MM'-'dd'T'HH':'mm':'ss['.'SSS]['Z']")

    try {
        format.parse(restOfDateTime)
    } catch (e: DateTimeParseException) {
        if (errorCode != null) throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7", "SAMLCore.1.3.3_a", errorCode)
        else throw SAMLComplianceException.create("XMLDatatypesSchema.3.2.7", "SAMLCore.1.3.3_a")
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