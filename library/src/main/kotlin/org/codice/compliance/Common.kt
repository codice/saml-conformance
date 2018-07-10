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
import org.w3c.tidy.Tidy
import java.io.File
import java.io.StringWriter
import java.nio.charset.StandardCharsets
import java.util.Properties
import javax.xml.parsers.DocumentBuilderFactory
import javax.xml.transform.OutputKeys
import javax.xml.transform.Transformer
import javax.xml.transform.TransformerFactory
import kotlin.test.currentStackTrace

const val IMPLEMENTATION_PATH = "implementation.path"
const val DEFAULT_IMPLEMENTATION_PATH = "implementations/ddf"
const val USER_LOGIN = "user.login"
const val TEST_SP_METADATA_PROPERTY = "test.sp.metadata"
const val LENIENT_ERROR_VERIFICATION = "lenient.error.verification"

class Common {
    companion object {
        private val SUPPORTED_BINDINGS = mutableSetOf(
                SamlProtocol.Binding.HTTP_POST,
                SamlProtocol.Binding.HTTP_REDIRECT
        )

        private val IDP_METADATA_STRING by lazy {
            requireNotNull(System.getProperty(IMPLEMENTATION_PATH)) {
                "Value required for $IMPLEMENTATION_PATH System property."
            }

            File(System.getProperty(IMPLEMENTATION_PATH)).walkTopDown().first {
                it.name.endsWith("idp-metadata.xml")
            }.readText()
        }

        /**
         * Parses and returns the idp metadata
         */
        val idpMetadataObject by lazy {
            IdpMetadata().apply {
                setMetadata(IDP_METADATA_STRING)
            }
        }

        private val TEST_SP_METADATA by lazy {
            requireNotNull(System.getProperty(TEST_SP_METADATA_PROPERTY)) {
                "Value required for $TEST_SP_METADATA_PROPERTY System property."
            }

            File(System.getProperty(TEST_SP_METADATA_PROPERTY)).readText()
        }

        /**
         * Parses and returns the sp metadata
         */
        fun parseSpMetadata(): Map<String, EntityInformation> {
            return SPMetadataParser.parse(TEST_SP_METADATA, SUPPORTED_BINDINGS)
        }

        /**
         * Returns SSO url of the passed in binding from the IdP's metadata
         */
        fun getSingleSignOnLocation(binding: String): String? {
            return idpMetadataObject
                    .descriptor
                    ?.singleSignOnServices
                    ?.first { it.binding == binding }
                    ?.location
        }

        /**
         * Returns SLO url of the passed in binding from the IdP's metadata
         */
        fun getSingleLogoutLocation(binding: String): String? {
            return idpMetadataObject
                    .descriptor
                    ?.singleLogoutServices
                    ?.first { it.binding == binding }
                    ?.location
        }

        /**
         * Generates an xml document from an input string
         */
        fun buildDom(inputXml: String): Node {
            return DocumentBuilderFactory.newInstance().apply {
                isNamespaceAware = true
            }.newDocumentBuilder()
                    .parse(tidy(inputXml).byteInputStream())
                    .documentElement
        }

        private fun tidy(input: String): String {
            if (!"""(?i:.*<html.*)""".toRegex(RegexOption.DOT_MATCHES_ALL).matches(input)) {
                return input
            }
            input.byteInputStream().use { inStr ->
                return StringWriter().use { outStr ->
                    Tidy().apply {
                        setConfigurationFromProps(Properties().apply {
                            setProperty("doctype", "omit")
                        })
                    }.parse(inStr, outStr)
                    outStr.toString()
                }
            }
        }

        fun runningAgainstDDF() = System.getProperty(IMPLEMENTATION_PATH).contains(
                DEFAULT_IMPLEMENTATION_PATH)
    }
}

/** Extensions functions **/
fun Log.debugWithSupplier(message: () -> String) {
    if (this.logLevel == LogLevel.DEBUG) {
        val callSite = currentStackTrace()[1]
        this.debug("${message()} [(${callSite.fileName}:${callSite.lineNumber})]")
    }
}

@Suppress("TooGenericExceptionCaught")
fun String.prettyPrintXml(): String {
    return try {
        // Escape all ampersands because Keycloak does not properly escape it in POST responses
        // which causes the transform to fail.
        val escapedString = this.replace("""&([^;]+(?!(?:\\\\w|;)))""".toRegex(),
                { match -> "&amp;${match.value.removePrefix("&")}" })

        Common.buildDom(escapedString).prettyPrintXml()
    } catch (e: Exception) {
        Log.debugWithSupplier { "'$this' is not valid XML." }
        this
    }
}

fun String.debugPrettyPrintXml(header: String?) {
    Log.debugWithSupplier {
        val headerVal = if (header != null) "$header:\n\n" else ""
        "$headerVal ${this.prettyPrintXml()}"
    }
}

internal fun createTransformer(): Transformer {
    return TransformerFactory.newInstance().newTransformer().apply {
        setOutputProperty(OutputKeys.ENCODING, StandardCharsets.UTF_8.name())
        setOutputProperty(OutputKeys.INDENT, "yes")
        setOutputProperty(OutputKeys.METHOD, "html")
        setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes")
        setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2")
    }
}
