package org.codice.compliance.core

import org.apache.commons.lang3.StringUtils
import org.codice.compliance.SAMLComplianceException
import org.w3c.dom.Node
import java.net.URI

var ids = mutableListOf<String>()

/**
 * Verify common data types against the core specification
 *
 * 1.3 Common Data Types
 */
fun verifyCommonDataType(response: Node) {
    var i = response.childNodes.length - 1

    while (i >= 0) {
        val child = response.childNodes.item(i)
        verifyStringValues(child)
        verifyUriValues(child)
        verifyTimeValues(child)
        verifyIdValues(child)

        if (child.hasChildNodes())
            verifyCommonDataType(child)
        i -= 1
    }
    ids = mutableListOf()
}

/**
 * Verify values of type string
 *
 * 1.3.1 String Values
 */
fun verifyStringValues(node: Node) {
    if (node.attributes?.getNamedItemNS("http://www.w3.org/2001/XMLSchema-instance", "type")
            ?.textContent?.contains("string") == true
            && StringUtils.isBlank(node.textContent))
        throw SAMLComplianceException.create("SAMLCore.1.3.1_a")
}

/**
 * Verify values of type anyURI
 *
 * 1.3.2 URI Values
 */
fun verifyUriValues(node: Node) {
    // todo - make sure uri absolute check is correct
    if (node.attributes?.getNamedItemNS("http://www.w3.org/2001/XMLSchema-instance", "type")
            ?.textContent?.contains("anyURI") == true
            && StringUtils.isBlank(node.textContent)
            && !URI.create(node.textContent).isAbsolute)
        throw SAMLComplianceException.create("SAMLCore.1.3.2_a")
}

/**
 * Verify values of type time
 *
 * 1.3.3 Time Values
 */
fun verifyTimeValues(node: Node) {
    if (node.attributes?.getNamedItemNS("http://www.w3.org/2001/XMLSchema-instance", "type")
            ?.textContent?.contains("dateTime") == true) {
        // todo - jacob add date time verification HERE
        // string called child.textContent
        // error code - SAMLCore.1.3.3_a
    }
}

/**
 * Verify values of type ID
 *
 * 1.3.4 ID and ID Reference Values
 */
fun verifyIdValues(node: Node) {
    if (node.attributes?.getNamedItemNS("http://www.w3.org/2001/XMLSchema-instance", "type")
            ?.textContent?.contains("ID") == true)
        if (ids.contains(node.textContent))
            throw SAMLComplianceException.create("SAMLCore.1.3.4_b")
        else ids.add(node.textContent)
}