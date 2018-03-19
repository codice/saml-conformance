package org.codice.compliance

class SAMLComplianceException : Exception {

    private constructor(message: String) : super(message)
    private constructor(message: String, cause: Throwable) : super(message, cause)

    companion object {
        fun create(vararg codes: SAMLSpecRefMessage, message: String, cause: Throwable? = null):
                SAMLComplianceException {
            val samlExceptions = codes.map(Companion::readCode)
                    .fold("SAML Specification References:\n") { acc, s ->
                        "$acc\n$s"
                    }

            if (cause != null) {
                return SAMLComplianceException("$message\n\n$samlExceptions\n", cause)
            } else {
                return SAMLComplianceException("$message\n\n$samlExceptions\n")
            }
        }

        fun createWithPropertyReqMessage(section: String, property: String, parent: String): SAMLComplianceException {
            return SAMLComplianceException("$section: $property is required in $parent.")
        }

        fun createWithPropertyInvalidMessage(code: SAMLSpecRefMessage, property: String, propertyValue: String?):
                SAMLComplianceException {
            return SAMLComplianceException("The $property value of $propertyValue is invalid.\n\n${readCode(code)}")
        }

        fun createWithPropertyNotEqualMessage(code: SAMLSpecRefMessage,
                                              property: String,
                                              propertyValue: String?,
                                              otherValue: String?): SAMLComplianceException {
            return SAMLComplianceException("The $property value of $propertyValue is not equal to $otherValue." +
                    "\n\n${readCode(code)}")
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
