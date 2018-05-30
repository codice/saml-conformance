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
import org.codice.compliance.utils.TestCommon.Companion.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.TestCommon.Companion.PARTIAL_LOGOUT
import org.codice.compliance.utils.TestCommon.Companion.SUCCESS
import org.codice.compliance.utils.TestCommon.Companion.createDefaultLogoutRequest
import org.codice.compliance.utils.TestCommon.Companion.createDefaultLogoutResponse
import org.codice.compliance.utils.TestCommon.Companion.loginAndGetCookies
import org.codice.compliance.utils.TestCommon.Companion.logoutRequestRelayState
import org.codice.compliance.utils.TestCommon.Companion.sendPostLogoutMessage
import org.codice.compliance.utils.TestCommon.Companion.signAndEncodePostRequestToString
import org.codice.compliance.utils.TestCommon.Companion.useDSAServiceProvider
import org.codice.compliance.utils.TestCommon.Companion.useDefaultServiceProvider
import org.codice.compliance.utils.determineBinding
import org.codice.compliance.utils.getBindingVerifier
import org.codice.compliance.verification.core.requests.CoreLogoutRequestProtocolVerifier
import org.codice.compliance.verification.core.responses.CoreLogoutResponseProtocolVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST

class PostSLOTest : StringSpec() {

    init {
        RestAssured.useRelaxedHTTPSValidation()

        "POST LogoutResponse Test - Single SP" {
            val cookies = loginAndGetCookies(HTTP_POST)

            val logoutRequest = createDefaultLogoutRequest(HTTP_POST)
            val encodedRequest = signAndEncodePostRequestToString(logoutRequest)
            val response = sendPostLogoutMessage(encodedRequest, cookies)

            val samlResponseDom = response.getBindingVerifier().decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                response.determineBinding()).verify()
        }

        "POST LogoutResponse Test - Multiple SPs" {
            val cookies = loginAndGetCookies(HTTP_POST, multipleSP = true)

            val logoutRequest = createDefaultLogoutRequest(HTTP_POST)
            val encodedRequest = signAndEncodePostRequestToString(logoutRequest)
            val secondSPLogoutRequest = sendPostLogoutMessage(encodedRequest, cookies)

            useDSAServiceProvider()
            val samlLogoutRequestDom = secondSPLogoutRequest.getBindingVerifier().apply {
                isSamlRequest = true
            }.decodeAndVerify()
            CoreLogoutRequestProtocolVerifier(samlLogoutRequestDom,
                secondSPLogoutRequest.determineBinding()).verify()

            val secondSPLogoutResponse = createDefaultLogoutResponse(samlLogoutRequestDom, true)
            val encodedSecondSPLogoutResponse =
                signAndEncodePostRequestToString(secondSPLogoutResponse, logoutRequestRelayState)
            val logoutResponse = sendPostLogoutMessage(encodedSecondSPLogoutResponse, cookies)

            useDefaultServiceProvider()
            val samlResponseDom = logoutResponse.getBindingVerifier().decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                logoutResponse.determineBinding()).verify()
        }

        "POST LogoutResponse Test With Relay State - Single SP" {
            val cookies = loginAndGetCookies(HTTP_POST)

            val logoutRequest = createDefaultLogoutRequest(HTTP_POST)
            val encodedRequest =
                signAndEncodePostRequestToString(logoutRequest, EXAMPLE_RELAY_STATE)
            val response = sendPostLogoutMessage(encodedRequest, cookies)

            val samlResponseDom = response.getBindingVerifier().apply {
                isRelayStateGiven = true
            }.decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                response.determineBinding()).verify()
        }

        "POST LogoutResponse Test With Relay State - Multiple SPs" {
            val cookies = loginAndGetCookies(HTTP_POST, multipleSP = true)

            val logoutRequest = createDefaultLogoutRequest(HTTP_POST)
            val encodedRequest =
                signAndEncodePostRequestToString(logoutRequest, EXAMPLE_RELAY_STATE)
            val secondSPLogoutRequest = sendPostLogoutMessage(encodedRequest, cookies)

            useDSAServiceProvider()
            val samlLogoutRequestDom = secondSPLogoutRequest.getBindingVerifier().apply {
                isSamlRequest = true
            }.decodeAndVerify()
            CoreLogoutRequestProtocolVerifier(samlLogoutRequestDom,
                secondSPLogoutRequest.determineBinding()).verify()

            val secondSPLogoutResponse = createDefaultLogoutResponse(samlLogoutRequestDom, true)
            val encodedSecondSPLogoutResponse =
                signAndEncodePostRequestToString(secondSPLogoutResponse, logoutRequestRelayState)
            val logoutResponse = sendPostLogoutMessage(encodedSecondSPLogoutResponse, cookies)

            useDefaultServiceProvider()
            val samlResponseDom = logoutResponse.getBindingVerifier().apply {
                isRelayStateGiven = true
            }.decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                logoutResponse.determineBinding()).verify()
        }

        "POST LogoutResponse Test With Error Logging Out From SP2 - Multiple SPs" {
            val cookies = loginAndGetCookies(HTTP_POST, multipleSP = true)

            val logoutRequest = createDefaultLogoutRequest(HTTP_POST)
            val encodedRequest =
                signAndEncodePostRequestToString(logoutRequest, EXAMPLE_RELAY_STATE)
            val secondSPLogoutRequest = sendPostLogoutMessage(encodedRequest, cookies)

            useDSAServiceProvider()
            val samlLogoutRequestDom = secondSPLogoutRequest.getBindingVerifier().apply {
                isSamlRequest = true
            }.decodeAndVerify()
            CoreLogoutRequestProtocolVerifier(samlLogoutRequestDom,
                secondSPLogoutRequest.determineBinding()).verify()

            // Send a response with an error saml status code
            val secondSPLogoutResponse = createDefaultLogoutResponse(samlLogoutRequestDom, false)
            val encodedSecondSPLogoutResponse =
                signAndEncodePostRequestToString(secondSPLogoutResponse, logoutRequestRelayState)
            val logoutResponse = sendPostLogoutMessage(encodedSecondSPLogoutResponse, cookies)

            useDefaultServiceProvider()
            val samlResponseDom = logoutResponse.getBindingVerifier().apply {
                isRelayStateGiven = true
            }.decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                logoutResponse.determineBinding(), listOf(SUCCESS, PARTIAL_LOGOUT)).verify()
        }
    }
}
