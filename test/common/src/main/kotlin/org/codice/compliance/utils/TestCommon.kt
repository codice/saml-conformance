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
package org.codice.compliance.utils

import org.apache.cxf.helpers.DOMUtils
import org.apache.wss4j.common.saml.OpenSAMLUtil
import org.apache.wss4j.common.saml.builder.SAML2Constants
import org.apache.wss4j.common.util.DOM2Writer
import org.codice.compliance.Common
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.saml.plugin.IdpResponse
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.SimpleSign
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder
import org.w3c.dom.Node
import java.io.File
import java.net.URLClassLoader
import java.util.*
import javax.xml.parsers.DocumentBuilderFactory

class TestCommon {
    companion object {
        val XSI = "http://www.w3.org/2001/XMLSchema-instance"
        val ELEMENT = "http://www.w3.org/2001/04/xmlenc#Element"

        val idpMetadata = Common.parseIdpMetadata()
        val spMetadata = Common.parseSpMetadata()

        val SP_ISSUER = spMetadata.keys.first()
        val SP_INFO = spMetadata[SP_ISSUER]
        var ACS_URL = SP_INFO?.getAssertionConsumerService(SamlProtocol.Binding.HTTP_REDIRECT)?.url
        val ID = "a1chfeh0234hbifc1jjd3cb40ji0d49"
        val EXAMPLE_RELAY_STATE = "relay+State"
        val INCORRECT_RELAY_STATE = "RelayStateLongerThan80CharsIsIncorrectAccordingToTheSamlSpec" +
                "ItMustNotExceed80BytesInLength"

        private val DEPLOY_CL = getDeployDirClassloader()

        /**
         * Extend {@code IdpResponse} to creates a dom response from it's decoded saml response
         */
        fun IdpResponse.buildDom(): Node {
            return DocumentBuilderFactory.newInstance().apply {
                isNamespaceAware = true
            }.newDocumentBuilder()
                    .parse(this.decodedSamlResponse.byteInputStream())
                    .documentElement
        }

        /**
         * Generates and returns a POST Authn Request
         */
        fun generateAndRetrieveAuthnRequest(): String {
            OpenSAMLUtil.initSamlEngine()

            ACS_URL = SP_INFO?.getAssertionConsumerService(SamlProtocol.Binding.HTTP_POST)?.url
            val authnRequest = AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply {
                    value = SP_ISSUER
                }
                assertionConsumerServiceURL = ACS_URL
                id = ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = Common.getSingleSignOnLocation(SamlProtocol.POST_BINDING)
                protocolBinding = SamlProtocol.POST_BINDING
                nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
                    allowCreate = true
                    format = SAML2Constants.NAMEID_FORMAT_PERSISTENT
                    spNameQualifier = SP_ISSUER
                }
            }

            SimpleSign().signSamlObject(authnRequest)

            val doc = DOMUtils.createDocument().apply {
                appendChild(createElement("root"))
            }

            val requestElement = OpenSAMLUtil.toDom(authnRequest, doc)
            return DOM2Writer.nodeToString(requestElement)
        }

        fun <T> getServiceProvider(type: Class<T>): T {
            return ServiceLoader.load(type, DEPLOY_CL).first()
        }

        private fun getDeployDirClassloader(): ClassLoader {
            val pluginDeploy = System.getProperty("saml.plugin.deployDir")

            return if (pluginDeploy != null) {
                val walkTopDown = File(pluginDeploy).canonicalFile.walkTopDown()
                val jarUrls = walkTopDown.maxDepth(1)
                        .filter { it.name.endsWith(".jar") }
                        .map { it.toURI() }
                        .map { it.toURL() }
                        .toList()

                URLClassLoader(jarUrls.toTypedArray(), SAMLComplianceException::class.java.classLoader)
            } else SAMLComplianceException::class.java.classLoader
        }
    }
}
