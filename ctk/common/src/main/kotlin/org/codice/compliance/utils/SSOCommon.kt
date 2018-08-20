/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.utils

import io.restassured.RestAssured
import io.restassured.response.Response
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
        fun createDefaultAuthnRequest(
            binding: SamlProtocol.Binding,
            requestIssuer: String = currentSPIssuer,
            entityInfo: EntityInformation = currentSPEntityInfo
        ): AuthnRequest {
            REQUEST_ID = "a" + UUID.randomUUID().toString() // IDs have to start with a letter
            return AuthnRequestBuilder().buildObject().apply {
                issuer = IssuerBuilder().buildObject().apply { value = requestIssuer }
                assertionConsumerServiceURL = entityInfo.getAssertionConsumerService(HTTP_POST)?.url
                id = REQUEST_ID
                version = SAMLVersion.VERSION_20
                issueInstant = DateTime()
                destination = getSingleSignOnLocation(binding.uri)
                protocolBinding = HTTP_POST.uri
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
                .usingTheGlobalHttpSession()
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
        fun sendPostAuthnRequest(encodedRequest: String): Response {
            return RestAssured.given()
                .urlEncodingEnabled(false)
                .usingTheGlobalHttpSession()
                .body(encodedRequest)
                .contentType("application/x-www-form-urlencoded")
                .log()
                .ifValidationFails()
                .`when`()
                .post(getSingleSignOnLocation(POST_BINDING))
        }
    }
}
