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

import org.codice.security.saml.IdpMetadata
import org.codice.security.saml.SamlProtocol
import org.w3c.dom.Node
import java.io.File
import java.util.*

const val IDP_METADATA = "idp.metadata"

val SUPPORTED_BINDINGS = mutableSetOf(
        SamlProtocol.Binding.HTTP_POST,
        SamlProtocol.Binding.HTTP_REDIRECT
)

class SAMLComplianceException private constructor(message: String) : Exception(message) {
    companion object {
        private val BUNDLE = ResourceBundle.getBundle("ExceptionCodes")!!

        fun create(vararg codes: String): SAMLComplianceException {
            val msg = codes.map(Companion::readCode)
                    .fold("Errors:\n") { acc, s ->
                        "$acc\n$s"
                    }
            return SAMLComplianceException(msg)
        }

        fun createWithReqMessage(section: String, attribute: String, parent: String): SAMLComplianceException {
            return SAMLComplianceException("$section: $attribute is required in $parent.")
        }

        private fun readCode(code: String): String {
            return "${trimUnderscore(code)}: ${BUNDLE.getString(code)}"
        }

        private fun trimUnderscore(codeValue: String): String {
            val underscoreIndex = codeValue.indexOf("_")

            return if (underscoreIndex == -1) codeValue
            else codeValue.substring(0, underscoreIndex)
        }
    }
}

class Common {
    companion object {
        val PARSED_METADATA = File(System.getProperty(IDP_METADATA)).readText()

        /**
         * Parses and returns the idp metadata
         */
        fun parseIdpMetadata(): IdpMetadata {
            return IdpMetadata().apply {
                setMetadata(PARSED_METADATA)
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

/** Extensions to Node class **/

/**
 * Finds a Node's child by its name.
 *
 * @param name - Name of Assertions.children
 * @return list of Assertions.children matching the name provided
 */
fun Node.children(name: String): List<Node> {
    val childNodes = mutableListOf<Node>()
    var i = this.childNodes.length - 1
    while (i >= 0) {
        val child = this.childNodes.item(i)
        if (child.localName == name)
            childNodes.add(child); i -= 1
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