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
import org.codice.compliance.Common.Companion.getSingleSignOnLocation
import org.codice.compliance.utils.TestCommon.Companion.REQUEST_ID
import org.codice.compliance.utils.TestCommon.Companion.currentSPEntityInfo
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.security.saml.EntityInformation
import org.codice.security.saml.SamlProtocol
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.saml.SamlProtocol.POST_BINDING
import org.codice.security.saml.SamlProtocol.REDIRECT_BINDING
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import java.util.UUID

class SSOCommon {
    companion object {
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
    }
}
