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
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.apache.wss4j.common.saml.OpenSAMLUtil
import org.apache.wss4j.common.util.DOM2Writer
import org.codice.compliance.Common.Companion.idpMetadataObject
import org.codice.compliance.Common.Companion.parseSpMetadata
import org.codice.compliance.IMPLEMENTATION_PATH
import org.codice.compliance.DecoratedNode
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLGeneral_c
import org.codice.compliance.USER_LOGIN
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.utils.sign.SimpleSign
import org.codice.security.saml.IdpMetadata
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.Encoder.encodePostMessage
import org.codice.security.sign.Encoder.encodeRedirectMessage
import org.opensaml.core.xml.XMLObject
import org.opensaml.saml.common.SignableSAMLObject
import org.opensaml.saml.saml2.core.RequestAbstractType
import org.w3c.dom.Node
import java.io.File
import java.net.URI
import java.net.URLClassLoader
import java.util.Optional
import java.util.ServiceLoader
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KClass
import kotlin.reflect.KProperty

class TestCommon {
    companion object {
        private const val DEFAULT_SP_ISSUER = "https://samlhost:8993/services/saml"
        internal const val DSA_SP_ISSUER = "https://samlhostdsa:8994/services/samldsa"

        lateinit var REQUEST_ID: String

        @JvmField
        var currentSPIssuer = DEFAULT_SP_ISSUER

        // Used to return the relay state in the logout response. It's set by the binding verifiers.
        var logoutRequestRelayState: String? = null

        /*
         * All of these properties are lazy, so that unit tests do not have to have all of this
         * system-level information setup.
         */
        private val DEPLOY_CL by lazy {
            getDeployDirClassloader()
        }

        val username by lazy {
            System.getProperty(USER_LOGIN).split(":").first()
        }

        val idpMetadata by lazy {
            parseAndVerifyVersion()
        }

        private val spMetadata by lazy {
            parseSpMetadata()
        }

        private val DEFAULT_SP_ENTITY_INFO by lazy {
            checkNotNull(spMetadata[DEFAULT_SP_ISSUER])
        }

        internal val DSA_SP_ENTITY_INFO by lazy {
            checkNotNull(spMetadata[DSA_SP_ISSUER])
        }

        var currentSPEntityInfo by LazyVar {
            DEFAULT_SP_ENTITY_INFO
        }

        /**
         * Sets the current service provider to the https://samlhost:8993/services/saml
         */
        fun useDefaultServiceProvider() {
            currentSPIssuer = DEFAULT_SP_ISSUER
            currentSPEntityInfo = DEFAULT_SP_ENTITY_INFO
        }

        /**
         * Sets the current service provider to the https://samlhostdsa:8994/services/samldsa SP
         */
        fun useDSAServiceProvider() {
            currentSPIssuer = DSA_SP_ISSUER
            currentSPEntityInfo = DSA_SP_ENTITY_INFO
        }

        @JvmStatic
        fun getCurrentSPHostname(): String {
            return URI(currentSPIssuer).host
        }

        /**
         * Returns the Assertion Consumer Service URL or the Logout Service URL
         *
         * @param binding - the binding of the URL desired
         * @param node - the node dom is used to determine if it's a login
         * Response (ACS URL) or a LogoutResponse (Logout Service URL)
         */
        fun getServiceUrl(binding: SamlProtocol.Binding, node: Node): String? {
            if (node.localName == RESPONSE)
                return currentSPEntityInfo.getAssertionConsumerService(binding)?.url

            return currentSPEntityInfo.getLogoutService(binding)?.url
        }

        private fun parseAndVerifyVersion(): IdpMetadata {
            if (idpMetadataObject.descriptor.supportedProtocols.none { it.contains("2.0") })
                throw SAMLComplianceException.create(SAMLGeneral_c,
                        message = "The protocolSupportEnumeration's version specified in the " +
                                "metadata is not 2.0 and not supported by this conformance test " +
                                "kit.")
            return idpMetadataObject
        }

        /**
         * Encodes a Redirect Request
         * @return A string representation of the encoded input request
         */
        fun encodeRedirectRequest(samlObject: SignableSAMLObject): String {
            val samlType = if (samlObject is RequestAbstractType) SAML_REQUEST else SAML_RESPONSE
            val authnRequestString = samlObjectToString(samlObject)
            authnRequestString.debugPrettyPrintXml(samlType)
            return encodeRedirectMessage(authnRequestString)
        }

        /**
         * Signs a given SAML Object (Request or Response) and converts the object to a String
         * for a POST request.
         * @param samlObject - The object to sign and encode
         * @return The signed object as a String
         */
        fun signAndEncodePostRequestToString(samlObject: SignableSAMLObject,
                                             relayState: String? = null): String {
            val samlType = if (samlObject is RequestAbstractType) SAML_REQUEST else SAML_RESPONSE

            SimpleSign().signSamlObject(samlObject)
            val requestString = samlObjectToString(samlObject)
            requestString.debugPrettyPrintXml(samlType)

            return if (relayState == null) encodePostMessage(samlType, requestString)
            else encodePostMessage(samlType, requestString, relayState)
        }

        /**
         * Converts the {@param samlObject} to a String
         */
        private fun samlObjectToString(samlObject: XMLObject): String {
            val doc = DOMUtils.createDocument().apply {
                appendChild(createElement("root"))
            }

            val samlElement = OpenSAMLUtil.toDom(samlObject, doc)
            return DOM2Writer.nodeToString(samlElement)
        }

        fun <T : Any> getImplementation(type: KClass<T>): T {
            return ServiceLoader.load(type.java, DEPLOY_CL).first()
        }

        private fun getDeployDirClassloader(): ClassLoader {
            val pluginDeploy = System.getProperty(IMPLEMENTATION_PATH)
            requireNotNull(pluginDeploy) {
                "Value required for System property $IMPLEMENTATION_PATH."
            }

            val walkTopDown = File(pluginDeploy).canonicalFile.walkTopDown()
            val jarUrls = walkTopDown.maxDepth(1)
                    .filter { it.name.endsWith(".jar") }
                    .map { it.toURI() }
                    .map { it.toURL() }
                    .toList()

            check(jarUrls.isNotEmpty()) {
                "No plugins found in $IMPLEMENTATION_PATH; CTK can not operate."
            }
            return URLClassLoader(jarUrls.toTypedArray(),
                    SAMLComplianceException::class.java.classLoader)
        }
    }
}

class LazyVar<T>(val init: () -> T) : ReadWriteProperty<Any?, T> {

    private lateinit var value: Optional<T>

    override fun getValue(thisRef: Any?, property: KProperty<*>): T {
        if (!::value.isInitialized) {
            value = Optional.of(init())
        }
        return value.get()
    }

    override fun setValue(thisRef: Any?, property: KProperty<*>, value: T) {
        this.value = Optional.of(value)
    }
}

class NodeDecorator(private val node: Node, var hasEncryptedAssertion: Boolean = false,
                    var isSigned: Boolean = false) : DecoratedNode, Node by node {
    override fun getNode(): Node {
        return node
    }
}
