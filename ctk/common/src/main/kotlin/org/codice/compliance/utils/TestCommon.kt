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
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.saml.plugin.IdpPostResponse
import org.codice.compliance.saml.plugin.IdpRedirectResponse
import org.codice.compliance.saml.plugin.IdpResponse
import org.codice.compliance.utils.decorators.IdpResponseDecorator
import org.codice.compliance.utils.decorators.decorate
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
        const val SAML_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion"
        const val BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
        const val HOLDER_OF_KEY_URI = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
        const val ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
        const val NAMEID_ENCRYPTED = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"

        const val ASSERTION = "Assertion"
        const val TYPE = "Type"
        const val AUTHN_REQUEST = "AuthnRequest"
        const val SAML_VERSION = "2.0"
        const val ID = "a1chfeh0234hbifc1jjd3cb40ji0d49"
        const val EXAMPLE_RELAY_STATE = "relay+State"
        const val RELAY_STATE_GREATER_THAN_80_BYTES = "RelayStateLongerThan80CharsIsIncorrect" +
                "AccordingToTheSamlSpecItMustNotExceed80BytesInLength"
        const val MAX_RELAY_STATE_LEN = 80
        const val INCORRECT_ACS_URL = "https://incorrect.acs.url"
        const val INCORRECT_DESTINATION = "https://incorrect.destination.com"

        const val IDP_ERROR_RESPONSE_REMINDER_MESSAGE = "Make sure the IdP responds immediately " +
                "with a SAML error response (See section 3.2.1 in the SAML Core specification)"

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
        private val spMetadata = Common.parseSpMetadata()

        val idpMetadata = Common.parseIdpMetadata()
        val SP_ISSUER = spMetadata.keys.first()

        val acsUrl: Map<SamlProtocol.Binding, String?> by lazy {
            val spInfo = spMetadata[SP_ISSUER]
            if (spInfo == null) {
                emptyMap()
            } else {
                SamlProtocol.Binding.values()
                        .associate {
                            it to spInfo.getAssertionConsumerService(it)?.url
                        }
            }
        }

        /**
         * Converts the {@param authnRequest} to a String
         */
        fun authnRequestToString(authnRequest: AuthnRequest): String {
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

        /*
         * Since errors shouldn't be passed to user implementations, this acts as the "user
         * implementation" and parses the response into the correct idp object for further
         * processing.
         *
         * @param response The error response returned from the first interaction with the IdP under
         * test.
         * @return An {@code IdpResponse} object created from the error response.
         */
        // TODO Change HTTP status code to expect 302/303
        fun parseErrorResponse(response: Response): IdpResponseDecorator {
            return if (response.header("Location") != null) {
                parseRedirectErrorResponse(response).decorate()
            } else {
                IdpPostResponse(response).decorate()
            }
        }

        private fun parseRedirectErrorResponse(response: Response): IdpRedirectResponse {
            return IdpRedirectResponse.Builder().apply {
                httpStatusCode(response.statusCode)
                url(response.header("Location"))
            }.build()
        }

        /**
         * Provides a default request for testing
         * @return A valid Redirect AuthnRequest.
         */
        fun createDefaultAuthnRequest(binding: SamlProtocol.Binding): AuthnRequest {
            return AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply {
                    value = SP_ISSUER
                }
                assertionConsumerServiceURL = acsUrl[SamlProtocol.Binding.HTTP_POST]
                id = ID
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

fun IdpResponse.decorate(): IdpResponseDecorator {
    return when (this) {
        is IdpPostResponse -> decorate()
        is IdpRedirectResponse -> decorate()
        else -> throw UnsupportedOperationException()
    }
}
