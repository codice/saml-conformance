/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.core

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_1_3_1_a
import org.codice.compliance.SAMLCore_1_3_2_a
import org.codice.compliance.SAMLCore_1_3_3_a
import org.codice.compliance.SAMLCore_1_3_4_a
import org.codice.compliance.SAMLSpecRefMessage
import org.codice.compliance.attributeTextNS
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.ID
import org.codice.compliance.utils.XSI
import org.w3c.dom.Node
import java.net.URI

class CommonDataTypeVerifier {
    companion object {
        var ids = mutableListOf<String>()

        /** 1.3 Common Data Types **/
        fun verifyCommonDataType(samlDom: Node) {
            samlDom.recursiveChildren().forEach {
                it.attributeTextNS(XSI, "type")?.let { type ->
                    when {
                        type.contains("string") -> verifyStringValue(it)
                        type.contains("anyURI") -> verifyUriValue(it)
                        type.contains("dateTime") -> verifyDateTimeValue(it)
                        type.contains(ID) -> verifyIdValue(it)
                    }
                }
            }
        }

        /** 1.3.1 String Values **/
        fun verifyStringValue(node: Node?, errorCode: SAMLSpecRefMessage? = null) {
            if (node?.textContent.isNullOrBlank()) {
                val errorMessage = "The String value of ${node?.textContent} is invalid."
                if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_1_a,
                        message = errorMessage)
                else throw SAMLComplianceException.create(SAMLCore_1_3_1_a,
                        message = errorMessage)
            }
        }

        /** 1.3.2 URI Values **/
        fun verifyUriValue(node: Node?, errorCode: SAMLSpecRefMessage? = null) {
            verifyUriValue(node?.textContent, errorCode)
        }

        fun verifyUriValue(uri: String?, errorCode: SAMLSpecRefMessage? = null) {
            val errorMessage = "The URI value of [$uri] is invalid."
            try {
                if (uri.isNullOrBlank() || !URI.create(uri).isAbsolute) {
                    if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                            SAMLCore_1_3_2_a,
                            message = errorMessage)
                    else throw SAMLComplianceException.create(SAMLCore_1_3_2_a,
                            message = errorMessage)
                }
            } catch (e: IllegalArgumentException) {
                if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_2_a,
                        message = errorMessage)
                else throw SAMLComplianceException.create(SAMLCore_1_3_2_a,
                        message = errorMessage)
            }
        }

        /** 1.3.3 Time Values **/
        fun verifyDateTimeValue(node: Node?, errorCode: SAMLSpecRefMessage? = null) {
            if (node == null || !node.textContent.endsWith("Z")) {
                val errorMessage = "The time date value of [${node?.textContent}] is not in UTC."
                if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_3_a,
                        message = errorMessage)
                else throw SAMLComplianceException.create(SAMLCore_1_3_3_a,
                        message = errorMessage)
            }
        }

        /** 1.3.4 ID and ID Reference Values **/
        fun verifyIdValue(node: Node?, errorCode: SAMLSpecRefMessage? = null) {
            if (node == null || ids.contains(node.textContent)) {
                val errorMessage = "The ID value of [${node?.textContent}] is not unique."
                if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_4_a,
                        message = errorMessage)
                else throw SAMLComplianceException.create(SAMLCore_1_3_4_a,
                        message = errorMessage)
            } else ids.add(node.textContent)
        }
    }
}
