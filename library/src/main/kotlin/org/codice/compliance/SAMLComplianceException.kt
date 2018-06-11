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

import de.jupf.staticlog.Log
import de.jupf.staticlog.core.LogLevel
import org.w3c.dom.Node

class SAMLComplianceException : Exception {

    private constructor(message: String) : super(message)
    private constructor(message: String,
                        cause: Throwable) : super(message, cause)

    companion object {
        private const val IDP_ERROR_RESPONSE_REMINDER_MESSAGE = "Make sure the IdP responds " +
            "immediately with a SAML error response (See section 3.2.1 in the SAML Core " +
            "specification)"

        fun create(vararg codes: SAMLSpecRefMessage,
                   message: String,
                   cause: Throwable? = null,
                   node: Node? = null):
                SAMLComplianceException {
            val samlExceptions = codes.map(Companion::readCode)
                    .fold("\tSAML Specification References:\n") { acc, s ->
                        "$acc\n\t$s"
                    }

            return if (cause != null) {
                SAMLComplianceException("$message\n\n$samlExceptions\n\n" +
                        "${node?.debugPrettyPrintXml() ?: ""}\n", cause)
            } else {
                SAMLComplianceException("$message\n\n$samlExceptions\n\n" +
                        "${node?.debugPrettyPrintXml() ?: ""}\n")
            }
        }

        @Suppress("LongParameterList")
        fun createWithPropertyMessage(vararg codes: SAMLSpecRefMessage,
                                      property: String,
                                      actual: String?,
                                      expected: String? = null,
                                      node: Node? = null): SAMLComplianceException {
            val samlExceptions = codes.map(Companion::readCode)
                    .fold("\tSAML Specification References:\n") { acc, s ->
                        "$acc\n\t$s"
                    }
            return if (expected == null) {
                SAMLComplianceException("The $property value of $actual is invalid.\n\n" +
                        "$samlExceptions\n\n" + (node?.debugPrettyPrintXml() ?: ""))
            } else {
                SAMLComplianceException("The $property value of $actual is not equal to " +
                        "$expected.\n\n$samlExceptions\n\n${node?.debugPrettyPrintXml() ?: ""}")
            }
        }

        fun recreateExceptionWithErrorMessage(exception: SAMLComplianceException):
            SAMLComplianceException {
            return if (exception.cause != null) {
                SAMLComplianceException(
                    "${exception.message}$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                    exception.cause)
            } else {
                SAMLComplianceException(
                    "${exception.message}$IDP_ERROR_RESPONSE_REMINDER_MESSAGE")
            }
        }

        private fun readCode(code: SAMLSpecRefMessage): String {
            return "${trimRefQualifier(code.name)}: ${code.message}"
        }

        private fun trimRefQualifier(codeValue: String): String? {
            return """([a-zA-Z]*(_[\d*])*)([_][a-z])?"""
                    .toRegex()
                    .find(codeValue)
                    ?.groupValues
                    ?.get(1)
        }
    }
}

private fun Node.debugPrettyPrintXml(): String? {
    return if (Log.logLevel == LogLevel.DEBUG) {
        this.prettyPrintXml()
    } else {
        null
    }
}
