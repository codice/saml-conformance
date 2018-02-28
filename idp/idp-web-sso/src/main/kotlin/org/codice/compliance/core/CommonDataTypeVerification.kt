package org.codice.compliance.core

import org.apache.commons.lang3.StringUtils
import org.codice.compliance.SAMLComplianceException
import org.w3c.dom.Node
import java.net.URI

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
            verifyStringValues(child)
        if (typeAttribute?.textContent?.contains("anyURI") == true)
            verifyUriValues(child)
        if (typeAttribute?.textContent?.contains("dateTime") == true)
            verifyTimeValues(child)
        if (typeAttribute?.textContent?.contains("ID") == true)
            verifyIdValues(child)

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
fun verifyStringValues(node: Node) {
    if (StringUtils.isBlank(node.textContent))
        throw SAMLComplianceException.create("SAMLCore.1.3.1_a")
}

/**
 * Verify values of type anyURI
 *
 * 1.3.2 URI Values
 */
fun verifyUriValues(node: Node) {
    // todo - make sure uri absolute check is correct
    if (StringUtils.isBlank(node.textContent)
            && !URI.create(node.textContent).isAbsolute)
        throw SAMLComplianceException.create("SAMLCore.1.3.2_a")
}

/**
 * Verify values of type dateTime
 *
 * 1.3.3 Time Values
 */
fun verifyTimeValues(node: Node) {
    // todo - jacob add date time verification HERE
    // string called child.textContent
    // error code - SAMLCore.1.3.3_a
}

/**
 * Verify values of type ID
 *
 * 1.3.4 ID and ID Reference Values
 */
fun verifyIdValues(node: Node) {
    if (ids.contains(node.textContent))
        throw SAMLComplianceException.create("SAMLCore.1.3.4_b")
    else ids.add(node.textContent)
}