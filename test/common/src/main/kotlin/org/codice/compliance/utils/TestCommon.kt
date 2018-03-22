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
import org.codice.compliance.PLUGIN_DIR_PROPERTY
import org.codice.compliance.SAMLComplianceException
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.SimpleSign
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder
import java.io.File
import java.net.URLClassLoader
import java.util.ServiceLoader
import kotlin.reflect.KClass

class TestCommon {
    companion object {
        const val XSI = "http://www.w3.org/2001/XMLSchema-instance"
        const val ELEMENT = "http://www.w3.org/2001/04/xmlenc#Element"
        const val SAML_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion"
        const val HOLDER_OF_KEY_URI = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
        const val ID = "a1chfeh0234hbifc1jjd3cb40ji0d49"
        const val EXAMPLE_RELAY_STATE = "relay+State"
        const val INCORRECT_RELAY_STATE = "RelayStateLongerThan80CharsIsIncorrectAccordingToTheSamlSpec" +
                "ItMustNotExceed80BytesInLength"
        const val MAX_RELAYSTATE_LEN = 80

        val idpMetadata = Common.parseIdpMetadata()
        private val spMetadata = Common.parseSpMetadata()

        val SP_ISSUER = spMetadata.keys.first()
        private val SP_INFO = spMetadata[SP_ISSUER]

        var ACS_URL = SP_INFO?.getAssertionConsumerService(SamlProtocol.Binding.HTTP_REDIRECT)?.url

        private val DEPLOY_CL = getDeployDirClassloader()

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

        fun <T : Any> getServiceProvider(type: KClass<T>): T {
            return ServiceLoader.load(type.java, DEPLOY_CL).first()
        }

        private fun getDeployDirClassloader(): ClassLoader {
            val pluginDeploy = System.getProperty(PLUGIN_DIR_PROPERTY)
            requireNotNull(pluginDeploy) { "Value required for System property $PLUGIN_DIR_PROPERTY." }

            val walkTopDown = File(pluginDeploy).canonicalFile.walkTopDown()
            val jarUrls = walkTopDown.maxDepth(1)
                    .filter { it.name.endsWith(".jar") }
                    .map { it.toURI() }
                    .map { it.toURL() }
                    .toList()

            check(jarUrls.isNotEmpty()) { "No plugins found in $PLUGIN_DIR_PROPERTY; CTK can not operate." }
            return URLClassLoader(jarUrls.toTypedArray(), SAMLComplianceException::class.java.classLoader)
        }
    }
}
