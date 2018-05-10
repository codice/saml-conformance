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

import com.jayway.restassured.RestAssured
import com.jayway.restassured.response.Response
import org.apache.cxf.helpers.DOMUtils
import org.apache.wss4j.common.saml.OpenSAMLUtil
import org.apache.wss4j.common.util.DOM2Writer
import org.codice.compliance.Common
import org.codice.compliance.IMPLEMENTATION_PATH
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLGeneral_c
import org.codice.compliance.debugPrettyPrintXml
import org.codice.security.saml.IdpMetadata
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.Encoder
import org.codice.security.sign.SimpleSign
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import java.io.File
import java.net.URLClassLoader
import java.util.ServiceLoader
import kotlin.reflect.KClass

class TestCommon {
    companion object {
        const val XSI = "http://www.w3.org/2001/XMLSchema-instance"
        const val ELEMENT = "http://www.w3.org/2001/04/xmlenc#Element"
        const val ASSERTION_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion"
        const val PROTOCOL_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:protocol"
        const val BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
        const val HOLDER_OF_KEY_URI = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
        const val ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
        const val NAMEID_ENCRYPTED = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"
        const val PERSISTENT_ID = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        const val TRANSIENT_ID = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

        const val ID = "ID"
        const val ASSERTION = "Assertion"
        const val TYPE = "Type"
        const val FORMAT = "Format"
        const val SUBJECT = "Subject"
        const val VERSION = "Version"
        const val DESTINATION = "Destination"
        const val STATUS_CODE = "StatusCode"
        const val AUDIENCE = "Audience"
        const val SUBJECT_CONFIRMATION = "SubjectConfirmation"
        const val AUTHN_REQUEST = "AuthnRequest"
        const val AUTHN_STATEMENT = "AuthnStatement"
        const val NAME = "name"
        const val VALUE = "value"
        const val HIDDEN = "hidden"
        const val TYPE_LOWER = "type"
        const val ACTION = "action"
        const val LOCATION = "Location"
        const val SAML_ENCODING = "SAMLEncoding"
        const val SP_NAME_QUALIFIER = "SPNameQualifier"

        const val REQUEST_ID = "a1chfeh0234hbifc1jjd3cb40ji0d49"
        const val EXAMPLE_RELAY_STATE = "relay+State"
        const val RELAY_STATE_GREATER_THAN_80_BYTES = "RelayStateLongerThan80CharsIsIncorrect" +
                "AccordingToTheSamlSpecItMustNotExceed80BytesInLength"
        const val MAX_RELAY_STATE_LEN = 80
        const val INCORRECT_ACS_URL = "https://incorrect.acs.url"
        const val INCORRECT_DESTINATION = "https://incorrect.destination.com"

        const val REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester"
        private const val VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
        private const val SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
        private const val RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder"
        val TOP_LEVEL_STATUS_CODES = setOf(SUCCESS, REQUESTER, RESPONDER, VERSION_MISMATCH)

        const val KEYSTORE_PASSWORD = "org.apache.ws.security.crypto.merlin.keystore.password"
        const val PRIVATE_KEY_ALIAS = "org.apache.ws.security.crypto.merlin.keystore.alias"
        const val PRIVATE_KEY_PASSWORD =
                "org.apache.ws.security.crypto.merlin.keystore.private.password"

        private val DEPLOY_CL = getDeployDirClassloader()
        val idpMetadata = parseAndVerifyVersion()

        const val DEFAULT_SP_ISSUER = "https://samlhost:8993/services/saml"
        const val DSA_SP_ISSUER = "https://samlhostdsa:8993/services/samldsa"

        private val spMetadata = Common.parseSpMetadata()
        val DEFAULT_SP_ENTITY_INFO = checkNotNull(spMetadata[DEFAULT_SP_ISSUER])
        val DSA_SP_ENTITY_INFO = checkNotNull(spMetadata[DSA_SP_ISSUER])

        var CURRENT_SP_ISSUER = DEFAULT_SP_ISSUER
        var CURRENT_SP_ENTITY_INFO = DEFAULT_SP_ENTITY_INFO

        fun acsUrl(binding: SamlProtocol.Binding): String? {
            return CURRENT_SP_ENTITY_INFO.getAssertionConsumerService(binding)?.url
        }

        private fun parseAndVerifyVersion(): IdpMetadata {
            val metadata = Common.parseIdpMetadata()
            if (metadata.descriptor.supportedProtocols.none { it.contains("2.0") })
                throw SAMLComplianceException.create(SAMLGeneral_c,
                    message = "The protocolSupportEnumeration's version specified in the metadata" +
                        " is not 2.0 and not supported by this conformance test kit.")
            return metadata
        }

        /**
         * Converts the {@param authnRequest} to a String
         */
        private fun authnRequestToString(authnRequest: AuthnRequest): String {
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

        /**
         * Provides a default request for testing
         * @return A valid Redirect AuthnRequest.
         */
        fun createDefaultAuthnRequest(binding: SamlProtocol.Binding): AuthnRequest {
            return AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply { value = CURRENT_SP_ISSUER }
                assertionConsumerServiceURL = acsUrl(SamlProtocol.Binding.HTTP_POST)
                id = REQUEST_ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = Common.getSingleSignOnLocation(binding.uri)
                protocolBinding = binding.uri
                isForceAuthn = false
                setIsPassive(false)
            }
        }

        /**
         * Submits a request to the IdP with the given parameters.
         * @return The IdP response
         */
        fun sendRedirectAuthnRequest(queryParams: Map<String, String>): Response {
            return RestAssured.given()
                    .urlEncodingEnabled(false)
                    .params(queryParams)
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .get(Common.getSingleSignOnLocation(SamlProtocol.REDIRECT_BINDING))
        }

        /**
         * Submits a request to the IdP with the given encoded request.
         * @return The IdP response
         */
        fun sendPostAuthnRequest(encodedRequest: String): Response {
            return RestAssured.given()
                    .urlEncodingEnabled(false)
                    .body(encodedRequest)
                    .contentType("application/x-www-form-urlencoded")
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .post(Common.getSingleSignOnLocation(SamlProtocol.POST_BINDING))
        }

        /**
         * Encodes an AuthnRequest
         * @return A string representation of the encoded input request
         */
        fun encodeAuthnRequest(authnRequest: AuthnRequest): String {
            val authnRequestString = authnRequestToString(authnRequest)
            authnRequestString.debugPrettyPrintXml(AUTHN_REQUEST)
            return Encoder.encodeRedirectMessage(authnRequestString)
        }

        /**
         * Signs a given AuthnRequest and converts the object to a String for a POST request.
         * @return The signed AuthnRequest as a String
         */
        fun signAndEncodeToString(authnRequest: AuthnRequest, relayState: String? = null): String {
            SimpleSign().signSamlObject(authnRequest)
            val authnRequestString = authnRequestToString(authnRequest)
            authnRequestString.debugPrettyPrintXml(AUTHN_REQUEST)
            return if (relayState == null) Encoder.encodePostMessage(authnRequestString)
            else Encoder.encodePostMessage(authnRequestString, relayState)
        }
    }
}
