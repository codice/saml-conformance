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
    // todo - jacob add date time verification HERE
    // string called child.textContent
    // error code - SAMLCore.1.3.3_a
    // also have
    // if (errorCode != null) throw SAMLComplianceException.create("SAMLCore.1.3.3_a", errorCode)
    // else throw SAMLComplianceException.create("SAMLCore.1.3.3_a")
    // when throwing the error
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