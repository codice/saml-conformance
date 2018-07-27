/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.core

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_8_2_2_a
import org.codice.compliance.SAMLCore_8_2_3_a
import org.codice.compliance.SAMLCore_8_3_2_a
import org.codice.compliance.SAMLCore_8_3_6_a
import org.codice.compliance.SAMLCore_8_3_6_b
import org.codice.compliance.SAMLCore_8_3_7_a
import org.codice.compliance.SAMLCore_8_3_7_b
import org.codice.compliance.SAMLCore_8_3_7_c
import org.codice.compliance.SAMLCore_8_3_7_d
import org.codice.compliance.SAMLCore_8_3_8_a
import org.codice.compliance.attributeNode
import org.codice.compliance.attributeText
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.ENTITY
import org.codice.compliance.utils.FORMAT
import org.codice.compliance.utils.PERSISTENT_ID
import org.codice.compliance.utils.SP_NAME_QUALIFIER
import org.codice.compliance.utils.TRANSIENT_ID
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.compliance.Common.Companion.idpMetadataObject
import org.w3c.dom.DOMException
import org.w3c.dom.Node
import java.net.URI
import java.net.URISyntaxException
import javax.xml.parsers.DocumentBuilderFactory

internal class SamlDefinedIdentifiersVerifier(val node: Node) {

    companion object {
        internal const val ENTITY_ID_MAX_LEN = 1024
        internal const val ID_VALUE_LENGTH_LIMIT = 256

        internal const val ATTRIBUTE_NAME_FORMAT_UNSPECIFIED =
                "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified"
        internal const val ATTRIBUTE_NAME_FORMAT_URI =
                "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
        internal const val ATTRIBUTE_NAME_FORMAT_BASIC =
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"

        internal const val NAME_ID_FORMAT_EMAIL =
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        // acquired from emailregex.com
        @Suppress("StringLiteralDuplication")
        private val EMAIL_REGEX =
                """
                |((?:[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*|"(?:[\x01-\x08\
                |x0b\x0c\x0e-\x1f\x21\x23-\x5b\x5d-\x7f]|\\[\x01-\x09\x0b\x0c\x0e-\x7f])*")@(?:(?:[a
                |-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]*[a-z0-9])?|\[(?:(?:25[0-5]|2[
                |0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?|[a-z0-9-]*
                |[a-z0-9]:(?:[\x01-\x08\x0b\x0c\x0e-\x1f\x21-\x5a\x53-\x7f]|\\[\x01-\x09\x0b\x0c\x0e
                |-\x7f])+)\]))
                """.trimMargin().replace("\\s".toRegex(), "")
    }

    /** 8 SAML-Defined Identifiers */
    fun verify() {
        verifyAttributeNameFormatIdentifiers()
        verifyEmailAddressIdentifier()
        verifyPersistentIdentifiers()
        verifyTransientIdentifiers()
        verifyEntityIdentifiers()
    }

    /** 8.2 URI/Basic name attribute formats */
    private fun verifyAttributeNameFormatIdentifiers() {
        node.recursiveChildren("Attribute").forEach {
            val name = it.attributeText("Name") ?: return
            val nameFormatText = it.attributeText("NameFormat") ?: return

            when (nameFormatText) {
                ATTRIBUTE_NAME_FORMAT_URI -> {
                    try {
                        URI(name)
                    } catch (e: URISyntaxException) {
                        throw SAMLComplianceException.create(
                                SAMLCore_8_2_2_a,
                                message = "Attribute name does not match its declared format",
                                node = node
                        )
                    }
                }
                ATTRIBUTE_NAME_FORMAT_BASIC -> {
                    try {
                        DocumentBuilderFactory.newInstance()
                                .newDocumentBuilder()
                                .newDocument()
                                .createElement(name)
                    } catch (e: DOMException) {
                        throw SAMLComplianceException.create(
                                SAMLCore_8_2_3_a,
                                message = "Attribute name does not match its declared format",
                                node = node
                        )
                    }
                }
            }
        }
    }

    /** 8.3.2 Email Address */
    private fun verifyEmailAddressIdentifier() {
        node.recursiveChildren()
                .filter { it.attributeText("Format") == NAME_ID_FORMAT_EMAIL }
                .forEach {
                    if (!it.textContent.matches(EMAIL_REGEX.toRegex()))
                        throw SAMLComplianceException.create(SAMLCore_8_3_2_a,
                                message = "The content [${it.textContent}] of the Identifier " +
                                        "[${it.localName}] was not in the format specified by " +
                                        "the Format attribute [$NAME_ID_FORMAT_EMAIL]",
                                node = it)
                }
    }

    /** 8.3.6 Entity Identifier */
    private fun verifyEntityIdentifiers() {
        node.recursiveChildren().filter { it.attributeText(FORMAT) == ENTITY }
                .forEach { checkEntityIdentifier(it) }
    }

    private fun checkEntityIdentifier(node: Node) {
        if (node.attributeNode("NameQualifier") != null ||
                node.attributeNode(SP_NAME_QUALIFIER) != null ||
                node.attributeNode("SPProvidedID") != null) {
            throw SAMLComplianceException.create(SAMLCore_8_3_6_a,
                    message = "Entity Identifier included a disallowed attribute.",
                    node = node)
        }
        node.textContent?.let {
            if (it.length > ENTITY_ID_MAX_LEN) {
                throw SAMLComplianceException.create(SAMLCore_8_3_6_b,
                        message = "Length of URI [$it] is [${it.length}]",
                        node = node)
            }
        }
    }

    /** 8.3.7 Persistent Identifier */
    private fun verifyPersistentIdentifiers() {
        node.recursiveChildren()
                .filter { it.attributeText(FORMAT) == PERSISTENT_ID }
                .forEach {
                    if (it.textContent != null && it.textContent.length > ID_VALUE_LENGTH_LIMIT)
                        throw SAMLComplianceException.create(SAMLCore_8_3_7_a,
                                message = "The length of the Persistent ID's value " +
                                        "[${it.textContent.length}] was greater than " +
                                        "$ID_VALUE_LENGTH_LIMIT characters.",
                                node = it)

                    it.attributeText("NameQualifier")?.let { nameQualifier ->
                        if (nameQualifier != idpMetadataObject.entityId)
                            throw SAMLComplianceException.create(SAMLCore_8_3_7_b,
                                    SAMLCore_8_3_7_c,
                                    message = "The Persistent ID's NameQualifier " +
                                            "[$nameQualifier] is not equal to " +
                                            "${idpMetadataObject.entityId}",
                                    node = it)
                    }

                    it.attributeText(SP_NAME_QUALIFIER)?.let { spNameQualifier ->
                        if (spNameQualifier != currentSPIssuer)
                            throw SAMLComplianceException.create(SAMLCore_8_3_7_d,
                                    message = "The Persistent ID's SPNameQualifier  " +
                                            "[$spNameQualifier]isn't equal to $currentSPIssuer",
                                    node = it)
                    }
                }
    }

    /** 8.3.8 Transient Identifier */
    private fun verifyTransientIdentifiers() {
        node.recursiveChildren()
                .filter { it.attributeText(FORMAT) == TRANSIENT_ID }
                .filter { it.textContent != null }
                .forEach {
                    if (it.textContent.length > ID_VALUE_LENGTH_LIMIT)
                        throw SAMLComplianceException.create(SAMLCore_8_3_8_a,
                                message = "The length of the Transient ID's value " +
                                        "[${it.textContent.length}]was greater than " +
                                        "$ID_VALUE_LENGTH_LIMIT characters.",
                                node = it)

                    CommonDataTypeVerifier.verifyIdValue(it, SAMLCore_8_3_8_a)
                }
    }
}
