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
package org.codice.compliance

import org.w3c.dom.Node

class SAMLComplianceException : Exception {

    private constructor(message: String) : super(message)
    private constructor(message: String, cause: Throwable) : super(message, cause)

    companion object {
        fun create(vararg codes: SAMLSpecRefMessage,
                   message: String,
                   cause: Throwable? = null,
                   node: Node? = null):
                SAMLComplianceException {
            val samlExceptions = codes.map(Companion::readCode)
                    .fold("SAML Specification References:\n") { acc, s ->
                        "$acc\n$s"
                    }

            return if (cause != null) {
                SAMLComplianceException("$message\n\n$samlExceptions\n\n" +
                        "${node?.prettyPrintXml() ?: ""}\n", cause)
            } else {
                SAMLComplianceException("$message\n\n$samlExceptions\n\n" +
                        "${node?.prettyPrintXml() ?: ""}\n")
            }
        }

        fun createWithXmlPropertyReqMessage(section: String,
                                            property: String,
                                            parent: String,
                                            node: Node? = null): SAMLComplianceException {
            return SAMLComplianceException("$section: $property is required in $parent.\n\n" +
                    (node?.prettyPrintXml() ?: ""))
        }

        @Suppress("LongParameterList")
        fun createWithPropertyMessage(code: SAMLSpecRefMessage,
                                      property: String,
                                      actual: String?,
                                      expected: String? = null,
                                      node: Node? = null): SAMLComplianceException {
            return if (expected == null) {
                SAMLComplianceException("The $property value of $actual is invalid.\n\n" +
                        "${readCode(code)}\n\n" + (node?.prettyPrintXml() ?: ""))
            } else {
                SAMLComplianceException("The $property value of $actual is not equal to " +
                        "$expected.\n\n${readCode(code)}\n\n${node?.prettyPrintXml() ?: ""}")
            }
        }

        private fun readCode(code: SAMLSpecRefMessage): String {
            return "${trimUnderscore(code.name)}: ${code.message}"
        }

        private fun trimUnderscore(codeValue: String): String {
            val underscoreIndex = codeValue.lastIndexOf("_")
            val trimmedCodeValue = if (underscoreIndex == -1) codeValue
            else codeValue.substring(0, underscoreIndex)

            return trimmedCodeValue.replace("_", ".")
        }
    }
}
