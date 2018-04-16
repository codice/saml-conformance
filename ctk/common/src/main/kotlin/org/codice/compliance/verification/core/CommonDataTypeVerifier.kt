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
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon.Companion.XSI
import org.w3c.dom.Node
import java.net.URI

class CommonDataTypeVerifier {
    companion object {
        var ids = mutableListOf<String>()

        /** 1.3 Common Data Types **/
        fun verifyCommonDataType(samlDom: Node) {
            samlDom.recursiveChildren().forEach {
                it.attributes?.getNamedItemNS(XSI, "type")?.textContent?.let { type ->
                    when {
                        type.contains("string") -> verifyStringValues(it)
                        type.contains("anyURI") -> verifyUriValues(it)
                        type.contains("dateTime") -> verifyDateTimeValues(it)
                        type.contains("ID") -> verifyIdValues(it)
                    }
                }

                if (it.hasChildNodes())
                    verifyCommonDataType(it)
            }
        }

        /** 1.3.1 String Values **/
        fun verifyStringValues(node: Node, errorCode: SAMLSpecRefMessage? = null) {
            if (StringUtils.isBlank(node.textContent)) {
                val errorMessage = "The String value of ${node.textContent} is invalid."
                if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_1_a,
                        message = errorMessage)
                else throw SAMLComplianceException.create(SAMLCore_1_3_1_a,
                        message = errorMessage)
            }
        }

        /** 1.3.2 URI Values **/
        fun verifyUriValues(node: Node, errorCode: SAMLSpecRefMessage? = null) {
            if (StringUtils.isBlank(node.textContent)
                    || !URI.create(node.textContent).isAbsolute) {
                val errorMessage = "The URI value of ${node.textContent} is invalid."
                if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_2_a,
                        message = errorMessage)
                else throw SAMLComplianceException.create(SAMLCore_1_3_2_a,
                        message = errorMessage)
            }
        }

        /** 1.3.3 Time Values **/
        fun verifyDateTimeValues(node: Node, errorCode: SAMLSpecRefMessage? = null) {
            if (!node.textContent.endsWith("Z")) {
                val errorMessage = "The time date value of ${node.textContent} is not in UTC."
                if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_3,
                        message = errorMessage)
                else throw SAMLComplianceException.create(SAMLCore_1_3_4,
                        message = errorMessage)
            }
        }

        /** 1.3.4 ID and ID Reference Values **/
        fun verifyIdValues(node: Node, errorCode: SAMLSpecRefMessage? = null) {
            if (ids.contains(node.textContent)) {
                val errorMessage = "The ID value of ${node.textContent} is not unique."
                if (errorCode != null) throw SAMLComplianceException.create(errorCode,
                        SAMLCore_1_3_4,
                        message = errorMessage)
                else throw SAMLComplianceException.create(SAMLCore_1_3_4,
                        message = errorMessage)
            } else ids.add(node.textContent)
        }
    }
}
