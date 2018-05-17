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
import io.kotlintest.TestCaseConfig
import io.kotlintest.TestResult
import io.kotlintest.extensions.TestCaseExtension
import io.kotlintest.extensions.TestCaseInterceptContext
import org.apache.cxf.helpers.DOMUtils
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.apache.wss4j.common.saml.OpenSAMLUtil
import org.apache.wss4j.common.util.DOM2Writer
import org.codice.compliance.Common
import org.codice.compliance.Common.Companion.getSingleLogoutLocation
import org.codice.compliance.Common.Companion.getSingleSignOnLocation
import org.codice.compliance.IMPLEMENTATION_PATH
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLGeneral_c
import org.codice.compliance.SAMLGeneral_d
import org.codice.compliance.attributeText
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.saml.plugin.IdpSSOResponder
import org.codice.compliance.utils.sign.SimpleSign
import org.codice.compliance.verification.binding.BindingVerifier.Companion.verifyHttpStatusCode
import org.codice.security.saml.EntityInformation
import org.codice.security.saml.IdpMetadata
import org.codice.security.saml.SamlProtocol
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.saml.SamlProtocol.POST_BINDING
import org.codice.security.saml.SamlProtocol.REDIRECT_BINDING
import org.codice.security.sign.Encoder.encodePostMessage
import org.codice.security.sign.Encoder.encodeRedirectMessage
import org.joda.time.DateTime
import org.opensaml.core.xml.XMLObject
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.common.SignableSAMLObject
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.core.LogoutRequest
import org.opensaml.saml.saml2.core.LogoutResponse
import org.opensaml.saml.saml2.core.RequestAbstractType
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder
import org.opensaml.saml.saml2.core.impl.LogoutResponseBuilder
import org.opensaml.saml.saml2.core.impl.NameIDBuilder
import org.opensaml.saml.saml2.core.impl.StatusBuilder
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder
import org.w3c.dom.Node
import java.io.File
import java.net.URI
import java.net.URLClassLoader
import java.util.Optional
import java.util.ServiceLoader
import java.util.UUID
import kotlin.properties.ReadWriteProperty
import kotlin.reflect.KClass
import kotlin.reflect.KProperty

@Suppress("TooManyFunctions", "LargeClass")
class TestCommon {
    companion object {
        const val XSI = "http://www.w3.org/2001/XMLSchema-instance"
        const val ELEMENT = "http://www.w3.org/2001/04/xmlenc#Element"
        const val ASSERTION_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion"
        const val PROTOCOL_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:protocol"
        const val BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
        const val HOLDER_OF_KEY_URI = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
        const val ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
        const val ENCRYPTED_ID = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"
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
        const val AUTHN_STATEMENT = "AuthnStatement"
        const val NAME = "name"
        const val VALUE = "value"
        const val HIDDEN = "hidden"
        const val TYPE_LOWER = "type"
        const val ACTION = "action"
        const val LOCATION = "Location"
        const val SAML_ENCODING = "SAMLEncoding"
        const val SP_NAME_QUALIFIER = "SPNameQualifier"

        lateinit var REQUEST_ID: String
        const val EXAMPLE_RELAY_STATE = "relay+State"
        const val RELAY_STATE_GREATER_THAN_80_BYTES = "RelayStateLongerThan80CharsIsIncorrect" +
            "AccordingToTheSamlSpecItMustNotExceed80BytesInLength"
        const val MAX_RELAY_STATE_LEN = 80
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

        private const val DEFAULT_SP_ISSUER = "https://samlhost:8993/services/saml"
        private const val DSA_SP_ISSUER = "https://samlhostdsa:8994/services/samldsa"

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

        val idpMetadata by lazy {
            parseAndVerifyVersion()
        }

        private val spMetadata by lazy {
            Common.parseSpMetadata()
        }

        private val DEFAULT_SP_ENTITY_INFO by lazy {
            checkNotNull(spMetadata[DEFAULT_SP_ISSUER])
        }

        private val DSA_SP_ENTITY_INFO by lazy {
            checkNotNull(spMetadata[DSA_SP_ISSUER])
        }

        var currentSPEntityInfo by LazyVar {
            DEFAULT_SP_ENTITY_INFO
        }

        object UseDSASigningSP : TestCaseExtension {
            override fun intercept(context: TestCaseInterceptContext,
                test: (TestCaseConfig, (TestResult) -> Unit) -> Unit,
                complete: (TestResult) -> Unit) {
                useDSAServiceProvider()
                test(context.config, { complete(it) })
                useDefaultServiceProvider()
            }
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
         * @param response - the response dom is used to determine if it's a login
         * Response (ACS URL) or a LogoutResponse (Logout Service URL)
         */
        fun getServiceUrl(binding: SamlProtocol.Binding, response: Node): String? {
            val nodeName = response.nodeName.split(":")[1]
            if (nodeName == "Response")
                return currentSPEntityInfo.getAssertionConsumerService(binding)?.url

            return currentSPEntityInfo.getLogoutService(binding)?.url
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

        /**
         * Provides a default request for testing
         * @return A valid Redirect AuthnRequest.
         */
        fun createDefaultAuthnRequest(binding: SamlProtocol.Binding,
            requestIssuer: String = currentSPIssuer,
            entityInfo: EntityInformation = currentSPEntityInfo): AuthnRequest {
            REQUEST_ID = "a" + UUID.randomUUID().toString() // IDs have to start with a letter
            return AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply { value = requestIssuer }
                assertionConsumerServiceURL = entityInfo.getAssertionConsumerService(HTTP_POST)?.url
                id = REQUEST_ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = getSingleSignOnLocation(binding.uri)
                protocolBinding = binding.uri
                isForceAuthn = false
                setIsPassive(false)
            }
        }

        /**
         * Submits a request to the IdP with the given parameters.
         * @return The IdP response
         */
        fun sendRedirectAuthnRequest(queryParams: Map<String, String>,
            cookies: Map<String, String> = mapOf()): Response {
            return RestAssured.given()
                    .urlEncodingEnabled(false)
                    .cookies(cookies)
                    .params(queryParams)
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .get(getSingleSignOnLocation(REDIRECT_BINDING))
        }

        /**
         * Submits a request to the IdP with the given encoded request.
         * @return The IdP response
         */
        fun sendPostAuthnRequest(encodedRequest: String,
            cookies: Map<String, String> = mapOf()): Response {
            return RestAssured.given()
                    .urlEncodingEnabled(false)
                    .cookies(cookies)
                    .body(encodedRequest)
                    .contentType("application/x-www-form-urlencoded")
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .post(getSingleSignOnLocation(POST_BINDING))
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
         * Attempts to login to service providers
         * @param binding - Binding used for login
         * @param singleSP - if true logs in with one sp, else logs in with both
         * @return cookies from first SP login, to be used in logout request
         */
        @Suppress("TooGenericExceptionCaught" /* Catching all Exceptions */)
        fun loginAndGetCookies(binding: SamlProtocol.Binding, singleSP: Boolean = true):
            Map<String, String> {
            try {
                val authnRequest by lazy {
                    createDefaultAuthnRequest(binding)
                }

                val secondRequest by lazy {
                    createDefaultAuthnRequest(binding, DSA_SP_ISSUER, DSA_SP_ENTITY_INFO)
                }

                return if (binding == HTTP_POST) {
                    val firstLoginResponse = loginPost(authnRequest)
                    val finalResponse = getImplementation(IdpSSOResponder::class)
                        .getResponseForPostRequest(firstLoginResponse)
                    if (!singleSP) {
                        useDSAServiceProvider()
                        loginPost(secondRequest, finalResponse.cookies)
                        useDefaultServiceProvider()
                    }
                    finalResponse.cookies
                } else {
                    val firstLoginResponse = loginRedirect(authnRequest)
                    val finalResponse = getImplementation(IdpSSOResponder::class)
                        .getResponseForRedirectRequest(firstLoginResponse)
                    if (!singleSP) {
                        useDSAServiceProvider()
                        loginRedirect(secondRequest, finalResponse.cookies)
                        useDefaultServiceProvider()
                    }
                    finalResponse.cookies
                }
            } catch (e: Exception) {
                throw SAMLComplianceException.create(SAMLGeneral_d,
                    message = "The logout test is unable to run because an error occurred while " +
                        "logging in.",
                    cause = e)
            }
        }

        private fun loginPost(request: AuthnRequest, cookies: Map<String, String> = mapOf()):
            Response {
            val response = sendPostAuthnRequest(
                signAndEncodePostRequestToString(request), cookies)
            verifyHttpStatusCode(response.statusCode)
            return response
        }

        private fun loginRedirect(request: AuthnRequest, cookies: Map<String, String> = mapOf()):
            Response {
            val queryParams = SimpleSign().signUriString(
                SAML_REQUEST,
                encodeRedirectRequest(request),
                null)

            val response = sendRedirectAuthnRequest(queryParams, cookies)
            verifyHttpStatusCode(response.statusCode)
            return response
        }

        /**
         * Provides a default logout request for testing
         * @return A valid LogoutRequest.
         */
        fun createDefaultLogoutRequest(binding: SamlProtocol.Binding): LogoutRequest {
            REQUEST_ID = "a" + UUID.randomUUID().toString() // IDs have to start with a letter
            return LogoutRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply { value = currentSPIssuer }
                id = REQUEST_ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = getSingleLogoutLocation(binding.uri)
                nameID = NameIDBuilder().buildObject().apply {
                    nameQualifier = idpMetadata.entityId
                    spNameQualifier = currentSPIssuer
                    format = PERSISTENT_ID
                    value = "admin"
                }
            }
        }

        /**
         * Provides a default logout response for testing
         * @param sendValidResponse - If true, returns a valid logout. If false, returns a saml
         * error response
         */
        @Suppress("NestedBlockDepth")
        fun createDefaultLogoutResponse(logoutRequestDom: Node, sendValidResponse: Boolean):
            LogoutResponse {
            return LogoutResponseBuilder().buildObject().apply {
                id = "a" + UUID.randomUUID().toString()
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                inResponseTo = logoutRequestDom.attributeText(ID)
                issuer = IssuerBuilder().buildObject().apply { value = currentSPIssuer }
                status = StatusBuilder().buildObject().apply {
                    statusCode = StatusCodeBuilder().buildObject().apply {
                        value = if (sendValidResponse) SUCCESS else RESPONDER
                    }
                }
            }
        }

        /**
         * Submits a logout request or response to the IdP with the given parameters.
         * @return The IdP response
         */
        fun sendRedirectLogoutMessage(queryParams: Map<String, String>,
            cookies: Map<String, String> = mapOf()): Response {
            return RestAssured.given()
                .urlEncodingEnabled(false)
                .redirects()
                .follow(false)
                .cookies(cookies)
                .params(queryParams)
                .log()
                .ifValidationFails()
                .`when`()
                .get(getSingleLogoutLocation(REDIRECT_BINDING))
        }

        /**
         * Submits a logout request or response to the IdP with the given encoded message.
         * @return The IdP response
         */
        fun sendPostLogoutMessage(encodedMessage: String,
            cookies: Map<String, String> = mapOf()): Response {
            return RestAssured.given()
                .urlEncodingEnabled(false)
                .cookies(cookies)
                .body(encodedMessage)
                .contentType("application/x-www-form-urlencoded")
                .log()
                .ifValidationFails()
                .`when`()
                .post(getSingleLogoutLocation(POST_BINDING))
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
