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

import io.kotlintest.TestCaseConfig
import io.kotlintest.provided.SLO
import io.kotlintest.specs.StringSpec
import io.restassured.RestAssured
import org.apache.cxf.rs.security.saml.sso.SSOConstants
import org.codice.compliance.Common.Companion.runningDDFProfile
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.utils.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.PARTIAL_LOGOUT
import org.codice.compliance.utils.SLOCommon.Companion.createDefaultLogoutRequest
import org.codice.compliance.utils.SLOCommon.Companion.createDefaultLogoutResponse
import org.codice.compliance.utils.SLOCommon.Companion.login
import org.codice.compliance.utils.SLOCommon.Companion.sendPostLogoutMessage
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.logoutRequestRelayState
import org.codice.compliance.utils.TestCommon.Companion.signAndEncodePostRequestToString
import org.codice.compliance.utils.TestCommon.Companion.useDSAServiceProvider
import org.codice.compliance.utils.TestCommon.Companion.useDefaultServiceProvider
import org.codice.compliance.utils.determineBinding
import org.codice.compliance.utils.getBindingVerifier
import org.codice.compliance.utils.sign.SimpleSign
import org.codice.compliance.verification.core.requests.CoreLogoutRequestProtocolVerifier
import org.codice.compliance.verification.core.responses.CoreLogoutResponseProtocolVerifier
import org.codice.compliance.verification.profile.SingleLogoutProfileVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.sign.Encoder
import org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_DSA_SHA256

class PostSLOTest : StringSpec() {
    override val defaultTestCaseConfig = TestCaseConfig(tags = setOf(SLO))

    init {
        RestAssured.useRelaxedHTTPSValidation()

        "POST LogoutResponse Test - Single SP" {
            login(HTTP_POST)

            val logoutRequest = createDefaultLogoutRequest(HTTP_POST)
            val encodedRequest = signAndEncodePostRequestToString(logoutRequest)
            val response = sendPostLogoutMessage(encodedRequest)

            val samlResponseDom = response.getBindingVerifier().decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                response.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlResponseDom).verifyLogoutResponse()
        }

        "POST LogoutResponse Test - Multiple SPs" {
            val ssoResponseDom = login(HTTP_POST, multipleSP = true)

            val logoutRequest = createDefaultLogoutRequest(HTTP_POST)
            val encodedRequest = signAndEncodePostRequestToString(logoutRequest)
            val secondSPLogoutRequest = sendPostLogoutMessage(encodedRequest)

            useDSAServiceProvider()
            val samlLogoutRequestDom = secondSPLogoutRequest.getBindingVerifier().apply {
                isSamlRequest = true
            }.decodeAndVerify()
            CoreLogoutRequestProtocolVerifier(samlLogoutRequestDom,
                secondSPLogoutRequest.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlLogoutRequestDom).verifyLogoutRequest(ssoResponseDom)

            val secondSPLogoutResponse =
                    createDefaultLogoutResponse(samlLogoutRequestDom, true)
            val encodedSecondSPLogoutResponse =
                signAndEncodePostRequestToString(secondSPLogoutResponse, logoutRequestRelayState)
            val logoutResponse = sendPostLogoutMessage(encodedSecondSPLogoutResponse)

            useDefaultServiceProvider()
            val samlResponseDom = logoutResponse.getBindingVerifier().decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                logoutResponse.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlResponseDom).verifyLogoutResponse()
        }

        "POST LogoutResponse Test With Relay State - Single SP" {
            login(HTTP_POST)

            val logoutRequest = createDefaultLogoutRequest(HTTP_POST)
            val encodedRequest =
                signAndEncodePostRequestToString(logoutRequest, EXAMPLE_RELAY_STATE)
            val response = sendPostLogoutMessage(encodedRequest)

            val samlResponseDom = response.getBindingVerifier().apply {
                isRelayStateGiven = true
            }.decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                response.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlResponseDom).verifyLogoutResponse()
        }

        "POST LogoutResponse Test With Relay State - Multiple SPs" {
            val ssoResponseDom = login(HTTP_POST, multipleSP = true)

            val logoutRequest = createDefaultLogoutRequest(HTTP_POST)
            val encodedRequest =
                signAndEncodePostRequestToString(logoutRequest, EXAMPLE_RELAY_STATE)
            val secondSPLogoutRequest = sendPostLogoutMessage(encodedRequest)

            useDSAServiceProvider()
            val samlLogoutRequestDom = secondSPLogoutRequest.getBindingVerifier().apply {
                isSamlRequest = true
            }.decodeAndVerify()
            CoreLogoutRequestProtocolVerifier(samlLogoutRequestDom,
                secondSPLogoutRequest.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlLogoutRequestDom).verifyLogoutRequest(ssoResponseDom)

            val secondSPLogoutResponse =
                    createDefaultLogoutResponse(samlLogoutRequestDom, true)
            val encodedSecondSPLogoutResponse =
                signAndEncodePostRequestToString(secondSPLogoutResponse, logoutRequestRelayState)
            val logoutResponse = sendPostLogoutMessage(encodedSecondSPLogoutResponse)

            useDefaultServiceProvider()
            val samlResponseDom = logoutResponse.getBindingVerifier().apply {
                isRelayStateGiven = true
            }.decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                logoutResponse.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlResponseDom).verifyLogoutResponse()
        }

        "POST LogoutResponse Test With Error Logging Out From SP2 - Multiple SPs" {
            val ssoResponseDom = login(HTTP_POST, multipleSP = true)

            val logoutRequest = createDefaultLogoutRequest(HTTP_POST)
            val encodedRequest =
                signAndEncodePostRequestToString(logoutRequest, EXAMPLE_RELAY_STATE)
            val secondSPLogoutRequest = sendPostLogoutMessage(encodedRequest)

            useDSAServiceProvider()
            val samlLogoutRequestDom = secondSPLogoutRequest.getBindingVerifier().apply {
                isSamlRequest = true
            }.decodeAndVerify()
            CoreLogoutRequestProtocolVerifier(samlLogoutRequestDom,
                secondSPLogoutRequest.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlLogoutRequestDom).verifyLogoutRequest(ssoResponseDom)

            // Send a response with an error saml status code
            val secondSPLogoutResponse =
                    createDefaultLogoutResponse(samlLogoutRequestDom, false)
            val encodedSecondSPLogoutResponse =
                signAndEncodePostRequestToString(secondSPLogoutResponse, logoutRequestRelayState)
            val logoutResponse = sendPostLogoutMessage(encodedSecondSPLogoutResponse)

            useDefaultServiceProvider()
            val samlResponseDom = logoutResponse.getBindingVerifier().apply {
                isRelayStateGiven = true
            }.decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                logoutResponse.determineBinding(), PARTIAL_LOGOUT).verify()
            SingleLogoutProfileVerifier(samlResponseDom).verifyLogoutResponse()
        }

        "DDF-Specific: POST LogoutRequest With SHA256 Signature Test - Single SP".config(
                enabled = runningDDFProfile()) {
            useDSAServiceProvider()
            login(HTTP_POST)

            val logoutRequest = createDefaultLogoutRequest(HTTP_POST)

            SimpleSign(ALGO_ID_SIGNATURE_DSA_SHA256).signSamlObject(logoutRequest)
            val requestString = TestCommon.samlObjectToString(logoutRequest)
            requestString.debugPrettyPrintXml(SSOConstants.SAML_REQUEST)

            val response = sendPostLogoutMessage(
                    Encoder.encodePostMessage(SSOConstants.SAML_REQUEST, requestString))

            val samlResponseDom = response.getBindingVerifier().decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                    response.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlResponseDom).verifyLogoutResponse()
        }
    }
}
