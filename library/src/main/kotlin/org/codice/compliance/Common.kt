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
import org.codice.security.saml.EntityInformation
import org.codice.security.saml.IdpMetadata
import org.codice.security.saml.SPMetadataParser
import org.codice.security.saml.SamlProtocol
import org.w3c.dom.Node
import java.io.File
import java.io.StringReader
import java.io.StringWriter
import java.nio.charset.StandardCharsets
import javax.xml.transform.OutputKeys
import javax.xml.transform.Transformer
import javax.xml.transform.TransformerFactory
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import javax.xml.transform.stream.StreamSource
import kotlin.test.currentStackTrace

const val IMPLEMENTATION_PATH = "implementation.path"
const val TEST_SP_METADATA_PROPERTY = "test.sp.metadata"

class Common {
    companion object {
        private val SUPPORTED_BINDINGS = mutableSetOf(
                SamlProtocol.Binding.HTTP_POST,
                SamlProtocol.Binding.HTTP_REDIRECT
        )

        private val IDP_METADATA by lazy {
            requireNotNull(System.getProperty(IMPLEMENTATION_PATH)) {
                "Value required for $IMPLEMENTATION_PATH System property."
            }

            File(System.getProperty(IMPLEMENTATION_PATH)).walkTopDown().first {
                it.name.endsWith("idp-metadata.xml")
            }.readText()
        }

        private val TEST_SP_METADATA by lazy {
            requireNotNull(System.getProperty(TEST_SP_METADATA_PROPERTY)) {
                "Value required for $TEST_SP_METADATA_PROPERTY System property."
            }

            File(System.getProperty(TEST_SP_METADATA_PROPERTY)).readText()
        }

        /**
         * Parses and returns the idp metadata
         */
        fun parseSpMetadata(): Map<String, EntityInformation> {
            return SPMetadataParser.parse(TEST_SP_METADATA, SUPPORTED_BINDINGS)
        }

        /**
         * Parses and returns the idp metadata
         */
        fun parseIdpMetadata(): IdpMetadata {
            return IdpMetadata().apply {
                setMetadata(IDP_METADATA)
            }
        }

        /**
         * Returns SSO url of the passed in binding from the IdP's metadata
         */
        fun getSingleSignOnLocation(binding: String): String? {
            return parseIdpMetadata()
                    .descriptor
                    ?.singleSignOnServices
                    ?.first { it.binding == binding }
                    ?.location
        }
    }
}

/** Extensions functions **/

/**
 * Finds a Node's child by its name.
 *
 * @param name - Name of Assertions.children
 * @return list of Assertions.children matching the name provided
 */
fun Node.children(name: String): List<Node> {
    val childNodes = mutableListOf<Node>()
    for (i in (this.childNodes.length - 1) downTo 0) {
        this.childNodes.item(i).apply {
            if (localName == name) childNodes.add(this)
        }
    }
    return childNodes
}

/**
 * Finds a Node's child by its name.
 *
 * @param name - Name of Assertions.children
 * @return list of Assertions.children matching the name provided
 */
fun Node.allChildren(name: String): List<Node> {
    val nodes = mutableListOf<Node>()
    var i = this.childNodes.length - 1
    while (i >= 0) {
        val child = this.childNodes.item(i)
        if (child.localName == name)
            nodes.add(child)
        nodes.addAll(child.allChildren(name)); i -= 1
    }
    return nodes
}

fun Node.prettyPrintXml(): String {
    val transformer = createTransformer()
    val output = StringWriter()
    transformer.transform(DOMSource(this), StreamResult(output))
    return output.toString()
}

fun Log.debugWithSupplier(message: () -> String) {
    if (this.logLevel == LogLevel.DEBUG) {
        val callSite = currentStackTrace()[1]
        this.debug("${message()} [(${callSite.fileName}:${callSite.lineNumber})]")
    }
}

fun String.prettyPrintXml(): String {
    val input = StreamSource(StringReader(this))
    val output = StreamResult(StringWriter())
    val transformer = createTransformer()
    transformer.transform(input, output)
    return output.writer.toString()
}

fun String.debugPrettyPrintXml(header: String?) {
    Log.debugWithSupplier {
        val headerVal = if (header == null) "$header:\n\n" else ""
        "$headerVal ${this.prettyPrintXml()}"
    }
}

private fun createTransformer(): Transformer {
    return TransformerFactory.newInstance().newTransformer().apply {
        setOutputProperty(OutputKeys.ENCODING, StandardCharsets.UTF_8.name())
        setOutputProperty(OutputKeys.INDENT, "yes")
        setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2")
    }
}
