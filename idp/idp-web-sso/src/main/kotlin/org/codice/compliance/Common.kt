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

import org.apache.cxf.helpers.DOMUtils
import org.apache.wss4j.common.saml.OpenSAMLUtil
import org.apache.wss4j.common.saml.builder.SAML2Constants
import org.apache.wss4j.common.util.DOM2Writer
import org.codice.security.saml.IdpMetadata
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.SimpleSign
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor
import org.w3c.dom.Document
import org.w3c.dom.Node
import java.io.File
import java.net.URLClassLoader
import java.util.*
import javax.xml.parsers.DocumentBuilderFactory

const val IDP_METADATA = "idp.metadata"
const val SP_ISSUER = "https://localhost:8993/services/saml"
const val DESTINATION = "https://localhost:8993/services/idp/login"
const val ACS = "https://localhost:8993/services/saml/sso"
const val ID = "a1chfeh0234hbifc1jjd3cb40ji0d49"
const val RELAY_STATE = "relay State"
const val INCORRECT_RELAY_STATE = "RelayStateLongerThan80CharsIsIncorrectAccordingToTheSamlSpecItMustNotExceed80BytesInLength"
val idpParsedMetadata = getIdpMetadata()

private val DEPLOY_CL = getDeployDirClassloader()

private fun getDeployDirClassloader(): ClassLoader {
    val pluginDeploy = System.getProperty("saml.plugin.deployDir")

    return if (pluginDeploy != null) {
        val walkTopDown = File(pluginDeploy).walkTopDown()
        val jarUrls = walkTopDown.maxDepth(1)
                .filter { it.name.endsWith(".jar") }
                .map { it.toURI() }
                .map { it.toURL() }
                .toList()

        URLClassLoader(jarUrls.toTypedArray(), SAMLComplianceException::class.java.classLoader)
    } else SAMLComplianceException::class.java.classLoader
}

fun <T> getServiceProvider(type: Class<T>): T {
    return ServiceLoader.load(type, DEPLOY_CL).first()
}

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
            return SAMLComplianceException(String.format("%s=%s is required in %s.", section, attribute, parent))
        }

        private fun readCode(code: String): String {
            return "${trimUnderscore(code)}: ${BUNDLE.getString(code)}"
        }

        private fun trimUnderscore(codeValue: String): String {
            val underscoreIndex = codeValue.indexOf("_")

            if (underscoreIndex == -1) return codeValue
            else return codeValue.substring(0, underscoreIndex)
        }
    }
}

/**
 * Parses and returns the idp metadata
 */
fun getIdpMetadata(): IDPSSODescriptor? {
    return IdpMetadata().apply {
        setMetadata(File(System.getProperty(IDP_METADATA)).readText())
    }.descriptor
}

/**
 * Creates a dom element given a string representation of xml
 */
fun buildDom(decodedMessage: String): Node {
    val docBuilder: DocumentBuilderFactory = DocumentBuilderFactory.newInstance()
    docBuilder.isNamespaceAware = true
    val xmlDoc: Document = docBuilder.newDocumentBuilder().parse(decodedMessage.byteInputStream())
    return xmlDoc.documentElement
}

/**
 * Generates and returns a POST Authn Request
 */
fun generateAndRetrieveAuthnRequest(): String {
    OpenSAMLUtil.initSamlEngine()
    val issuerObject = IssuerBuilder().buildObject().apply {
        value = SP_ISSUER
    }

    val authnRequest = AuthnRequestBuilder().buildObject().apply {
        issuer = issuerObject
        assertionConsumerServiceURL = ACS
        id = ID
        version = SAMLVersion.VERSION_20
        issueInstant = DateTime()
        destination = DESTINATION
        protocolBinding = SamlProtocol.POST_BINDING
        nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
            allowCreate = true
            format = SAML2Constants.NAMEID_FORMAT_PERSISTENT
            spNameQualifier = SP_ISSUER
        }
    }

    SimpleSign().signSamlObject(authnRequest)
    val doc = DOMUtils.createDocument()
    doc.appendChild(doc.createElement("root"))
    val requestElement = OpenSAMLUtil.toDom(authnRequest, doc)

    return DOM2Writer.nodeToString(requestElement)
}

/**
 * Returns SSO url of the passed in binding from the IdP's metadata
 */
fun getSingleSignonLocation(binding: String): String? {
    return getIdpMetadata()
            ?.singleSignOnServices
            ?.first { it.binding == binding }
            ?.location
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