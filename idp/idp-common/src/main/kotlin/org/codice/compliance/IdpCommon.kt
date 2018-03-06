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
import org.codice.security.saml.SPMetadataParser
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.SimpleSign
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder
import org.w3c.dom.Document
import org.w3c.dom.Node
import java.io.File
import java.net.URLClassLoader
import java.util.*
import javax.xml.parsers.DocumentBuilderFactory

const val SP_ISSUER = "https://localhost:8993/services/saml"
const val ACS_URL = "https://localhost:8993/services/saml/sso"
const val ID = "a1chfeh0234hbifc1jjd3cb40ji0d49"
const val EXAMPLE_RELAY_STATE = "relay+State"
const val INCORRECT_RELAY_STATE = "RelayStateLongerThan80CharsIsIncorrectAccordingToTheSamlSpecItMustNotExceed80BytesInLength"
val idpMetadata = parseIdpMetadata()
val spMetadataMap = parseSpMetadataMap()

private val DEPLOY_CL = getDeployDirClassloader()

class DeployDirClassloader

private fun getDeployDirClassloader(): ClassLoader {
    val pluginDeploy = System.getProperty("saml.plugin.deployDir")

    return if (pluginDeploy != null) {
        val walkTopDown = File(pluginDeploy).walkTopDown()
        val jarUrls = walkTopDown.maxDepth(1)
                .filter { it.name.endsWith(".jar") }
                .map { it.toURI() }
                .map { it.toURL() }
                .toList()

        URLClassLoader(jarUrls.toTypedArray(), DeployDirClassloader::class.java.classLoader)
    } else DeployDirClassloader::class.java.classLoader
}

fun <T> getServiceProvider(type: Class<T>): T {
    return ServiceLoader.load(type, DEPLOY_CL).first()
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
        assertionConsumerServiceURL = ACS_URL
        id = ID
        version = SAMLVersion.VERSION_20
        issueInstant = DateTime()
        destination = getSingleSignOnLocation(SamlProtocol.POST_BINDING)
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
