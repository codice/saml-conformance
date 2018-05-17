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
package org.codice.compliance.web.slo

import com.jayway.restassured.RestAssured
import io.kotlintest.specs.StringSpec
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.createDefaultLogoutRequest
import org.codice.compliance.utils.TestCommon.Companion.createDefaultLogoutResponse
import org.codice.compliance.utils.TestCommon.Companion.encodeRedirectRequest
import org.codice.compliance.utils.TestCommon.Companion.loginAndGetCookies
import org.codice.compliance.utils.TestCommon.Companion.sendRedirectLogoutMessage
import org.codice.compliance.utils.TestCommon.Companion.useDSAServiceProvider
import org.codice.compliance.utils.TestCommon.Companion.useDefaultServiceProvider
import org.codice.compliance.utils.determineBinding
import org.codice.compliance.utils.getBindingVerifier
import org.codice.compliance.utils.sign.SimpleSign
import org.codice.compliance.verification.core.requests.CoreLogoutRequestProtocolVerifier
import org.codice.compliance.verification.core.responses.CoreLogoutResponseProtocolVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT

class RedirectSLOTest : StringSpec() {

    init {
        RestAssured.useRelaxedHTTPSValidation()

        "Redirect LogoutRequest Test - Single SP" {
            val cookies = loginAndGetCookies(HTTP_REDIRECT)

            val logoutRequest = createDefaultLogoutRequest(HTTP_REDIRECT)
            val encodedRequest = encodeRedirectRequest(logoutRequest)
            val queryParams = SimpleSign().signUriString(
                SAML_REQUEST,
                encodedRequest,
                null)
            val response = sendRedirectLogoutMessage(queryParams, cookies)

            val samlResponseDom = response.getBindingVerifier().decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                response.determineBinding()).verify()
        }

        "Redirect LogoutResponse Test - Multiple SPs" {
            val cookies = loginAndGetCookies(HTTP_REDIRECT, singleSP = false)

            val logoutRequest = createDefaultLogoutRequest(HTTP_REDIRECT)
            val encodedRequest = encodeRedirectRequest(logoutRequest)
            val queryParams = SimpleSign().signUriString(
                SAML_REQUEST,
                encodedRequest,
                null)
            val secondSPLogoutRequest = sendRedirectLogoutMessage(queryParams, cookies)

            useDSAServiceProvider()
            val samlLogoutRequestDom = secondSPLogoutRequest.getBindingVerifier().apply {
                isSamlRequest = true
            }.decodeAndVerify()
            CoreLogoutRequestProtocolVerifier(samlLogoutRequestDom).verify()

            val secondSPLogoutResponse = createDefaultLogoutResponse(samlLogoutRequestDom, true)
            val encodedSecondSPLogoutResponse = encodeRedirectRequest(secondSPLogoutResponse)
            val secondSPResponseQueryParams = SimpleSign().signUriString(
                SAML_RESPONSE,
                encodedSecondSPLogoutResponse,
                null)
            val logoutResponse = sendRedirectLogoutMessage(secondSPResponseQueryParams, cookies)

            useDefaultServiceProvider()
            val samlResponseDom = logoutResponse.getBindingVerifier().decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                logoutResponse.determineBinding()).verify()
        }

        "Redirect LogoutRequest Test With Relay State - Single SP" {
            val cookies = loginAndGetCookies(HTTP_REDIRECT)

            val logoutRequest = createDefaultLogoutRequest(HTTP_REDIRECT)
            val encodedRequest = encodeRedirectRequest(logoutRequest)
            val queryParams = SimpleSign().signUriString(
                SAML_REQUEST,
                encodedRequest,
                EXAMPLE_RELAY_STATE)
            val response = sendRedirectLogoutMessage(queryParams, cookies)

            val samlResponseDom = response.getBindingVerifier().decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                response.determineBinding()).verify()
        }
    }
}
