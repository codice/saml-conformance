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
import org.codice.compliance.report.Report
import org.codice.compliance.report.Report.Section.CORE_1_3
import org.codice.compliance.utils.ID
import org.codice.compliance.utils.XSI
import org.w3c.dom.Node
import java.net.URI

class CommonDataTypeVerifier {
    companion object {
        private var ids = mutableListOf<String>()

        /** 1.3 Common Data Types **/
        fun verifyCommonDataType(samlDom: Node) {
            CORE_1_3.start()
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
            if (!node?.textContent.isNullOrBlank()) {
                return
            }

            val errorMessage = "The String value of ${node?.textContent} is invalid."
            Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_1_3_1_a,
                    message = errorMessage))

            if (errorCode != null) {
                Report.addExceptionMessage(SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_1_a,
                        message = errorMessage))
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
                    Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_1_3_2_a,
                            message = errorMessage))

                    if (errorCode != null) {
                        Report.addExceptionMessage(SAMLComplianceException.create(errorCode,
                                SAMLCore_1_3_2_a,
                                message = errorMessage))
                    }
                }
            } catch (e: IllegalArgumentException) {
                Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_1_3_2_a,
                        message = errorMessage))

                if (errorCode != null) {
                    Report.addExceptionMessage(SAMLComplianceException.create(errorCode,
                            SAMLCore_1_3_2_a,
                            message = errorMessage))
                }
            }
        }

        /** 1.3.3 Time Values **/
        fun verifyDateTimeValue(node: Node?, errorCode: SAMLSpecRefMessage? = null) {
            if (node != null && node.textContent.endsWith("Z")) {
                return
            }
            val errorMessage = "The time date value of [${node?.textContent}] is not in UTC."
            Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_1_3_3_a,
                    message = errorMessage))

            if (errorCode != null) {
                Report.addExceptionMessage(SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_3_a,
                        message = errorMessage))
            }
        }

        /** 1.3.4 ID and ID Reference Values **/
        fun verifyIdValue(node: Node?, errorCode: SAMLSpecRefMessage? = null) {
            if (node != null && !ids.contains(node.textContent)) {
                ids.add(node.textContent)
                return
            }
            val errorMessage = "The ID value of [${node?.textContent}] is not unique."
            Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_1_3_4_a,
                    message = errorMessage))

            if (errorCode != null) {
                Report.addExceptionMessage(SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_4_a,
                        message = errorMessage))
            }
        }
    }
}
