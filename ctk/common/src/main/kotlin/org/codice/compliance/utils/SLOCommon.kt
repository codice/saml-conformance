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

import io.restassured.RestAssured
import io.restassured.response.Response
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.codice.compliance.Common.Companion.getSingleLogoutLocation
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLGeneral_d
import org.codice.compliance.attributeText
import org.codice.compliance.saml.plugin.IdpSSOResponder
import org.codice.compliance.utils.SSOCommon.Companion.createDefaultAuthnRequest
import org.codice.compliance.utils.SSOCommon.Companion.sendPostAuthnRequest
import org.codice.compliance.utils.SSOCommon.Companion.sendRedirectAuthnRequest
import org.codice.compliance.utils.TestCommon.Companion.DSA_SP_ENTITY_INFO
import org.codice.compliance.utils.TestCommon.Companion.DSA_SP_ISSUER
import org.codice.compliance.utils.TestCommon.Companion.REQUEST_ID
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.compliance.utils.TestCommon.Companion.encodeRedirectRequest
import org.codice.compliance.utils.TestCommon.Companion.getImplementation
import org.codice.compliance.utils.TestCommon.Companion.idpMetadata
import org.codice.compliance.utils.TestCommon.Companion.signAndEncodePostRequestToString
import org.codice.compliance.utils.TestCommon.Companion.useDSAServiceProvider
import org.codice.compliance.utils.TestCommon.Companion.useDefaultServiceProvider
import org.codice.compliance.utils.TestCommon.Companion.username
import org.codice.compliance.utils.sign.SimpleSign
import org.codice.compliance.verification.binding.BindingVerifier.Companion.verifyHttpStatusCode
import org.codice.compliance.verification.core.responses.CoreAuthnRequestProtocolVerifier
import org.codice.security.saml.SamlProtocol
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.saml.SamlProtocol.POST_BINDING
import org.codice.security.saml.SamlProtocol.REDIRECT_BINDING
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.core.LogoutRequest
import org.opensaml.saml.saml2.core.LogoutResponse
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder
import org.opensaml.saml.saml2.core.impl.LogoutResponseBuilder
import org.opensaml.saml.saml2.core.impl.NameIDBuilder
import org.opensaml.saml.saml2.core.impl.StatusBuilder
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder
import org.w3c.dom.Node
import java.util.UUID

class SLOCommon {
    companion object {
        /**
         * Attempts to login from one or two Service Providers
         * @param binding - Binding used for login
         * @param multipleSP - if false logs in with one sp, else logs in with both
         * @return the first AuthnRequest
         */
        @Suppress("TooGenericExceptionCaught" /* Catching all Exceptions */)
        fun login(binding: SamlProtocol.Binding, multipleSP: Boolean = false): Node {
            var samlResponseDom: Node
            try {
                val authnRequest by lazy {
                    createDefaultAuthnRequest(binding)
                }

                val secondRequest by lazy {
                    createDefaultAuthnRequest(binding, DSA_SP_ISSUER, DSA_SP_ENTITY_INFO)
                }

                if (binding == HTTP_POST) {
                    val firstLoginResponse = loginPost(authnRequest)
                    samlResponseDom = getImplementation(IdpSSOResponder::class)
                            .getResponseForPostRequest(firstLoginResponse)
                            .apply {
                                GlobalSession.addCookies(cookies)
                            }.getBindingVerifier().decodeAndVerify().also {
                                CoreAuthnRequestProtocolVerifier(authnRequest,
                                        it).preProcess()
                            }

                    if (multipleSP) {
                        useDSAServiceProvider()
                        loginPost(secondRequest)
                        useDefaultServiceProvider()
                    }
                } else {
                    val firstLoginResponse = loginRedirect(authnRequest)
                    samlResponseDom = getImplementation(IdpSSOResponder::class)
                            .getResponseForRedirectRequest(firstLoginResponse)
                            .apply {
                                GlobalSession.addCookies(cookies)
                            }.getBindingVerifier().decodeAndVerify().also {
                                CoreAuthnRequestProtocolVerifier(authnRequest,
                                        it).preProcess()
                            }

                    if (multipleSP) {
                        useDSAServiceProvider()
                        loginRedirect(secondRequest)
                        useDefaultServiceProvider()
                    }
                }
                return samlResponseDom
            } catch (e: Exception) {
                throw SAMLComplianceException.create(SAMLGeneral_d,
                        message = "The logout test is unable to run because an error occurred " +
                                "while logging in.",
                        cause = e)
            }
        }

        private fun loginPost(request: AuthnRequest):
                Response {
            val response = sendPostAuthnRequest(
                    signAndEncodePostRequestToString(request))
            verifyHttpStatusCode(response.statusCode)
            return response
        }

        private fun loginRedirect(request: AuthnRequest):
                Response {
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodeRedirectRequest(request),
                    null)

            val response = sendRedirectAuthnRequest(queryParams)
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
                    value = username
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
        fun sendRedirectLogoutMessage(queryParams: Map<String, String>): Response {
            return RestAssured.given()
                    .urlEncodingEnabled(false)
                    .redirects()
                    .follow(false)
                    .usingTheGlobalHttpSession()
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
        fun sendPostLogoutMessage(encodedMessage: String): Response {
            return RestAssured.given()
                    .urlEncodingEnabled(false)
                    .usingTheGlobalHttpSession()
                    .body(encodedMessage)
                    .contentType("application/x-www-form-urlencoded")
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .post(getSingleLogoutLocation(POST_BINDING))
        }
    }
}
