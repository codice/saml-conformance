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
package org.codice.compliance.utils.schema

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_Schema
import org.codice.compliance.prettyPrintXml
import org.w3c.dom.Element
import org.w3c.dom.Node
import org.xml.sax.ErrorHandler
import org.xml.sax.SAXParseException
import javax.xml.XMLConstants
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.dom.DOMSource
import java.io.ByteArrayInputStream
import javax.xml.transform.TransformerFactory
import javax.xml.transform.stream.StreamResult
import java.io.ByteArrayOutputStream
import java.io.InputStream
import javax.xml.validation.SchemaFactory
import javax.xml.validation.Validator

class SchemaValidator {
    companion object {

        private const val EXTERNAL_SCHEMA_LOCATION =
                "http://apache.org/xml/properties/schema/external-schemaLocation"
        private const val CURRENT_ELEMENT_NODE =
                "http://apache.org/xml/properties/dom/current-element-node"
        private const val PROTOCOL_SCHEMA = "saml-schema-protocol-2.0.xsd"

        // Specify the schema to use for a given namespace, overriding its declared
        // schemaLocation. Used to avoid downloading external schemas
        private val schemaLocationOverrides = mapOf(
                "http://www.w3.org/2000/09/xmldsig#" to "xmldsig-core-schema.xsd",
                "http://www.w3.org/2001/04/xmlenc#" to "xenc-schema.xsd"
        )

        /**
         * Validate SAML against the protocol schema. Assumes that the message is well-formed
         */
        fun validateSAMLMessage(saml: Node) {
            validateSAML(nodeToInputStream(saml), PROTOCOL_SCHEMA)
        }

        private fun validateSAML(saml: InputStream, xsd: String) {
            // Load schema, overriding external schema references with local copies
            val schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI)
            schemaFactory.setProperty(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "file")
            schemaFactory.setProperty(EXTERNAL_SCHEMA_LOCATION, schemaLocationOverrides
                    .map {
                        val namespace = it.key
                        val localSchema = this::class.java.classLoader.getResource(it.value)
                        return@map "$namespace ${localSchema.toExternalForm()}"
                    }
                    .joinToString("\n")
            )
            val schema = schemaFactory.newSchema(this::class.java.classLoader.getResource(xsd))

            // Load SAML for validation
            val dbf = DocumentBuilderFactory.newInstance()
            dbf.isNamespaceAware = true
            val doc = dbf.newDocumentBuilder().parse(saml)

            // Validate
            val validator = schema.newValidator()
            val errorHandler = SAMLErrorHandler(validator)
            validator.errorHandler = errorHandler
            validator.validate(DOMSource(doc.documentElement))

            if (errorHandler.messages.isNotEmpty()) {
                val compiledErrors = errorHandler.messages.joinToString("\n")
                throw SAMLComplianceException.create(SAMLCore_Schema,
                        message = "Invalid SAML message\n$compiledErrors"
                )
            }
        }

        private fun nodeToInputStream(node: Node): InputStream {
            val outputStream = ByteArrayOutputStream()
            val xmlSource = DOMSource(node)
            val outputTarget = StreamResult(outputStream)
            TransformerFactory.newInstance().newTransformer().transform(xmlSource, outputTarget)
            return ByteArrayInputStream(outputStream.toByteArray())
        }
    }

    private class SAMLErrorHandler(validator: Validator) : ErrorHandler {
        private val xsdValidator = validator
        val messages = mutableListOf<String>()

        private fun getCurrentNode(): Element {
            return xsdValidator.getProperty(CURRENT_ELEMENT_NODE) as Element
        }

        private fun generateErrorMessage(severity: String, spe: SAXParseException) {
            val parseError = spe.localizedMessage
            val nodeXmlString = getCurrentNode().prettyPrintXml()
            messages.add("[$severity] $parseError\n$nodeXmlString")
        }

        override fun warning(spe: SAXParseException) {
            generateErrorMessage("Warning", spe)
        }

        override fun error(spe: SAXParseException) {
            generateErrorMessage("Error", spe)
        }

        override fun fatalError(spe: SAXParseException) {
            generateErrorMessage("Fatal Error", spe)
        }
    }
}
