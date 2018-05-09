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

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_8_1_2_a
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
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.compliance.utils.TestCommon.Companion.FORMAT
import org.codice.compliance.utils.TestCommon.Companion.PERSISTENT_ID
import org.codice.compliance.utils.TestCommon.Companion.SP_NAME_QUALIFIER
import org.codice.compliance.utils.TestCommon.Companion.TRANSIENT_ID
import org.codice.compliance.utils.TestCommon.Companion.idpMetadata
import org.w3c.dom.DOMException
import org.w3c.dom.Node
import java.net.URI
import java.net.URISyntaxException
import javax.xml.parsers.DocumentBuilderFactory

internal class SamlDefinedIdentifiersVerifier(val node: Node) {

    companion object {
        private const val ENTITY_ID_MAX_LEN = 1024
        private const val ID_VALUE_LENGTH_LIMIT = 256
        private const val ATTRIBUTE_NAME_FORMAT_URI =
                "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
        private const val ATTRIBUTE_NAME_FORMAT_BASIC =
                "urn:oasis:names:tc:SAML:2.0:attrname-format:basic"

        private const val EMAIL_URI = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        // acquired from http://regexlib.com/REDetails.aspx?regexp_id=2558
        @Suppress("StringLiteralDuplication")
        private const val EMAIL_REGEX =
                "^((([!#\$%&'*+\\-/=?^_`{|}~\\w])|([!#\$%&'*+\\-/=?^_`{|}~\\w][!#\$%&'*+\\-/=?^_`" +
                        "{|}~\\.\\w]{0,}[!#\$%&'*+\\-/=?^_`{|}~\\w]))[@]\\w+([-.]\\w+)*\\.\\w+([-" +
                        ".]\\w+)*)\$"

        private val RWEDC_URI_SET = setOf(
                "urn:oasis:names:tc:SAML:1.0:action:rwedc-negation",
                "urn:oasis:names:tc:SAML:1.0:action:rwedc"
        )
    }

    /** 8 SAML-Defined Identifiers */
    fun verify() {
        verifyActionNamespaceIdentifiers()
        verifyAttributeNameFormatIdentifiers()
        verifyNameIdentifierFormatIdentifiers()
        verifyPersistentIdentifiers()
        verifyTransientIdentifiers()
        verifyEntityIdentifiers()
    }

    /** 8.1.2 Read/Write/Execute/Delete/Control with Negation **/
    private fun verifyActionNamespaceIdentifiers() {
        // AuthzDecisionQuery is the only element where "Action" is found (Core 3.3.2.4)
        node.recursiveChildren("AuthzDecisionQuery").forEach({
            val actionList = createActionList(it)

            if (actionList.isNotEmpty()) {
                checkActionList(actionList)
            }
        })
    }

    private fun createActionList(query: Node): List<String> {
        return query.children("Action")
                .filter { it.attributeNode("Namespace")?.nodeValue in RWEDC_URI_SET }
                .map { it.nodeValue }
                .toList()
    }

    private fun checkActionList(actionList: List<String>) {
        val (negated, notNegated) = actionList.partition { it.startsWith("~") }
        notNegated.forEach {
            if ("~$it" in negated) {
                throw SAMLComplianceException.create(
                        SAMLCore_8_1_2_a,
                        message = "An \"AuthzDecisionQuery\" element contained an action and its " +
                                "negated form.",
                        node = node
                )
            }
        }
    }

    /** 8.2 URI/Basic name attribute formats */
    private fun verifyAttributeNameFormatIdentifiers() {
        node.recursiveChildren("Attribute").forEach {
            val name = it.attributeNode("Name")
            val nameFormatText = it.attributeText("NameFormat")
            if (name == null || nameFormatText == null) {
                return
            }

            when (nameFormatText) {
                ATTRIBUTE_NAME_FORMAT_URI -> {
                    try {
                        URI(name.textContent)
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
                                .createElement(name.textContent)
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

    /** 8.3 Name Identifier Format Identifiers */
    private fun verifyNameIdentifierFormatIdentifiers() {
        node.recursiveChildren()
                .filter { it.attributeText("Format") == EMAIL_URI }
                .forEach {
                    if (!it.textContent.matches(EMAIL_REGEX.toRegex()))
                        throw SAMLComplianceException.create(SAMLCore_8_3_2_a,
                                message = "The content of the Identifier [${it.localName}] was " +
                                        "not in the format specified by the Format attribute " +
                                        "[$EMAIL_URI]",
                                node = it
                        )
                }
    }

    /** 8.3.6 Entity Identifier */
    private fun verifyEntityIdentifiers() {
        node.recursiveChildren().filter { it.attributeText(TestCommon.FORMAT) == TestCommon.ENTITY }
            .forEach { checkEntityIdentifier(it) }
    }

    private fun checkEntityIdentifier(node: Node) {
        if (node.attributeNode("NameQualifier") != null ||
            node.attributeNode(SP_NAME_QUALIFIER) != null ||
            node.attributeNode("SPProvidedID") != null) {
            throw SAMLComplianceException.create(SAMLCore_8_3_6_a,
                message = "No Subject element found.",
                node = node)
        }
        node.nodeValue?.let {
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
                            "[${it.textContent.length}] was greater than $ID_VALUE_LENGTH_LIMIT " +
                            "characters.",
                        node = it)

                it.attributeText(SP_NAME_QUALIFIER)?.let { nameQualifier ->
                    if (nameQualifier != idpMetadata.entityId)
                        throw SAMLComplianceException.create(SAMLCore_8_3_7_b,
                            SAMLCore_8_3_7_c,
                            message = "The Persistent ID's NameQualifier [$nameQualifier] is not " +
                                "equal to ${idpMetadata.entityId}",
                            node = it)
                }

                it.attributeText(SP_NAME_QUALIFIER)?.let { spNameQualifier ->
                    if (spNameQualifier != currentSPIssuer )
                        throw SAMLComplianceException.create(SAMLCore_8_3_7_d,
                            message = "The Persistent ID's SPNameQualifier [$spNameQualifier] " +
                                "isn't equal to $currentSPIssuer",
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
                            "[${it.textContent.length}]was greater than $ID_VALUE_LENGTH_LIMIT " +
                            "characters.",
                        node = it)

                CommonDataTypeVerifier.verifyIdValue(it, SAMLCore_8_3_8_a)
            }
    }
}
