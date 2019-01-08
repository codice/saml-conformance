/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance

import de.jupf.staticlog.Log
import de.jupf.staticlog.core.LogLevel
import org.w3c.dom.Node

@Suppress("StringLiteralDuplication", "SpreadOperator")
class SAMLComplianceException : Exception {

    val section: Section

    val errorCodes: List<SAMLSpecRefMessage>

    private constructor(sec: Section, codes: Array<out SAMLSpecRefMessage>, message: String) :
            super(message) {
        errorCodes = listOf(*codes)
        section = sec
    }

    private constructor(sec: Section, codes: Collection<SAMLSpecRefMessage>, message: String) :
            super(message) {
        errorCodes = codes.toList()
        section = sec
    }

    private constructor(
        sec: Section,
        codes: Array<out SAMLSpecRefMessage>,
        message: String,
        cause: Throwable
    ) : super(message, cause) {
        errorCodes = listOf(*codes)
        section = sec
    }

    private constructor(
        sec: Section,
        codes: Collection<SAMLSpecRefMessage>,
        message: String,
        cause: Throwable
    ) : super(message, cause) {
        errorCodes = codes.toList()
        section = sec
    }

    companion object {
        private const val IDP_ERROR_RESPONSE_REMINDER_MESSAGE = "Make sure the IdP responds " +
                "immediately with a SAML error response (See section 3.2.1 in the SAML Core " +
                "specification)"

        /**
         * Creates a new SAMLComplianceException.
         *
         * @param codes - a code or a list of codes referencing the specification section
         * @param message - the exception's message
         * @param cause - the cause of the exception (optional)
         * @param node - the incorrect node that caused the exception (optional)
         * @return a SAMLComplianceException
         *
         * NOTE: The newly created SAMLComplianceException's section will be the section of the
         * FIRST code in {@param codes}.
         */
        fun create(
            vararg codes: SAMLSpecRefMessage,
            message: String,
            cause: Throwable? = null,
            node: Node? = null
        ): SAMLComplianceException {
            val samlExceptions = codes.map(Companion::readCode)
                    .fold("\tSAML Specification References:\n") { acc, s ->
                        "$acc\n\t$s"
                    }

            return if (cause != null) {
                SAMLComplianceException(codes[0].section, codes, "$message\n\n$samlExceptions\n\n" +
                        "${node?.debugPrettyPrintXml() ?: ""}\n", cause)
            } else {
                SAMLComplianceException(codes[0].section, codes, "$message\n\n$samlExceptions\n\n" +
                        "${node?.debugPrettyPrintXml() ?: ""}\n")
            }
        }

        /**
         * Creates a new SAMLComplianceException for a given {@param property}.
         *
         * @param codes - a code or a list of codes referencing the specification section
         * @param property - the property containing the incorrect value
         * @param actual - the incorrect value
         * @param expected - the correct value
         * @param node - the incorrect node that caused the exception (optional)
         * @return a SAMLComplianceException with a clear message of the expected and the actual
         * results
         *
         * NOTE: The newly created SAMLComplianceException's section will be the section of the
         * FIRST code in {@param codes}.
         */
        @Suppress("LongParameterList")
        fun createWithPropertyMessage(
            vararg codes: SAMLSpecRefMessage,
            property: String,
            actual: String?,
            expected: String? = null,
            node: Node? = null
        ): SAMLComplianceException {
            val samlExceptions = codes.map(Companion::readCode)
                    .fold("\tSAML Specification References:\n") { acc, s ->
                        "$acc\n\t$s"
                    }
            return if (expected == null) {
                SAMLComplianceException(codes[0].section, codes, "The $property value of $actual " +
                        "is invalid.\n\n$samlExceptions\n\n" + (node?.debugPrettyPrintXml() ?: ""))
            } else {
                SAMLComplianceException(codes[0].section, codes, "The $property value of $actual " +
                        "is not equal to $expected.\n\n$samlExceptions\n\n" +
                        (node?.debugPrettyPrintXml() ?: ""))
            }
        }

        /**
         * Creates a new SAMLComplianceException for a given {@param property}.
         *
         * @param codes - a code or a list of codes referencing the specification section
         * @param property - the property containing the incorrect value
         * @param actual - the incorrect value
         * @param expected - the correct value
         * @param node - the incorrect node that caused the exception (optional)
         * @return a SAMLComplianceException with a clear message of the expected and the actual
         * results
         *
         * NOTE: The newly created SAMLComplianceException's section will be the section of the
         * FIRST code in {@param codes}.
         */
        @Suppress("LongParameterList")
        fun createWithPropertyMessage(
            codes: Collection<SAMLSpecRefMessage>,
            property: String,
            actual: String?,
            expected: String? = null,
            node: Node? = null
        ): SAMLComplianceException {
            val samlExceptions = codes.map(Companion::readCode)
                    .fold("\tSAML Specification References:\n") { acc, s ->
                        "$acc\n\t$s"
                    }
            return if (expected == null) {
                SAMLComplianceException(codes.first().section, codes, "The $property value of " +
                        "$actual is invalid.\n\n$samlExceptions\n\n" +
                        (node?.debugPrettyPrintXml() ?: ""))
            } else {
                SAMLComplianceException(codes.first().section, codes, "The $property value of " +
                        "$actual is not equal to $expected.\n\n$samlExceptions\n\n" +
                        (node?.debugPrettyPrintXml() ?: ""))
            }
        }

        /**
         * Creates a new SAMLComplianceException for a given SAMLComplianceException.
         *
         * @param exception - the SAMLComplianceException to recreate
         * @return a new SAMLComplianceException
         */
        fun recreateExceptionWithErrorMessage(exception: SAMLComplianceException):
                SAMLComplianceException {
            return if (exception.cause != null) {
                SAMLComplianceException(exception.section, exception.errorCodes,
                        "${exception.message}$IDP_ERROR_RESPONSE_REMINDER_MESSAGE",
                        exception.cause)
            } else {
                SAMLComplianceException(exception.section, exception.errorCodes,
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

    /** The error codes of SAMLComplianceExceptions will determine their equality */
    override fun equals(other: Any?): Boolean {
        if (other !is SAMLComplianceException) return false
        return errorCodes == other.errorCodes
    }

    override fun hashCode(): Int {
        return errorCodes.hashCode()
    }
}

private fun Node.debugPrettyPrintXml(): String? {
    return if (Log.logLevel == LogLevel.DEBUG) {
        this.prettyPrintXml()
    } else {
        null
    }
}
