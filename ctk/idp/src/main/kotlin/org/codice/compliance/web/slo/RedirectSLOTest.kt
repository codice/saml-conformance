/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.web.slo

import io.kotlintest.TestCaseConfig
import io.kotlintest.provided.SLO
import io.kotlintest.specs.StringSpec
import io.restassured.RestAssured
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.codice.compliance.Common.Companion.runningDDFProfile
import org.codice.compliance.utils.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.PARTIAL_LOGOUT
import org.codice.compliance.utils.SLOCommon.Companion.createDefaultLogoutRequest
import org.codice.compliance.utils.SLOCommon.Companion.createDefaultLogoutResponse
import org.codice.compliance.utils.SLOCommon.Companion.login
import org.codice.compliance.utils.SLOCommon.Companion.sendRedirectLogoutMessage
import org.codice.compliance.utils.TestCommon.Companion.encodeRedirectRequest
import org.codice.compliance.utils.TestCommon.Companion.logoutRequestRelayState
import org.codice.compliance.utils.TestCommon.Companion.useDSAServiceProvider
import org.codice.compliance.utils.TestCommon.Companion.useDefaultServiceProvider
import org.codice.compliance.utils.determineBinding
import org.codice.compliance.utils.getBindingVerifier
import org.codice.compliance.utils.sign.SimpleSign
import org.codice.compliance.verification.core.requests.CoreLogoutRequestProtocolVerifier
import org.codice.compliance.verification.core.responses.CoreLogoutResponseProtocolVerifier
import org.codice.compliance.verification.profile.SingleLogoutProfileVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT
import org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_DSA_SHA256

class RedirectSLOTest : StringSpec() {
    override val defaultTestCaseConfig = TestCaseConfig(tags = setOf(SLO))

    init {
        RestAssured.useRelaxedHTTPSValidation()

        "Redirect LogoutRequest Test - Single SP" {
            val ssoResponseDom = login(HTTP_REDIRECT)

            val logoutRequest = createDefaultLogoutRequest(HTTP_REDIRECT, ssoResponseDom)
            val encodedRequest = encodeRedirectRequest(logoutRequest)
            val queryParams = SimpleSign().signUriString(
                SAML_REQUEST,
                encodedRequest,
                null)
            val response = sendRedirectLogoutMessage(queryParams)

            val samlResponseDom = response.getBindingVerifier().decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                response.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlResponseDom).verifyLogoutResponse()
        }

        "Redirect LogoutResponse Test - Multiple SPs" {
            val ssoResponseDom = login(HTTP_REDIRECT, multipleSP = true)

            val logoutRequest = createDefaultLogoutRequest(HTTP_REDIRECT, ssoResponseDom)
            val encodedRequest = encodeRedirectRequest(logoutRequest)
            val queryParams = SimpleSign().signUriString(
                SAML_REQUEST,
                encodedRequest,
                null)
            val secondSPLogoutRequest = sendRedirectLogoutMessage(queryParams)

            useDSAServiceProvider()
            val samlLogoutRequestDom = secondSPLogoutRequest.getBindingVerifier().apply {
                isSamlRequest = true
            }.decodeAndVerify()
            CoreLogoutRequestProtocolVerifier(samlLogoutRequestDom,
                secondSPLogoutRequest.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlLogoutRequestDom).verifyLogoutRequest(ssoResponseDom)

            val secondSPLogoutResponse =
                    createDefaultLogoutResponse(samlLogoutRequestDom, true)
            val encodedSecondSPLogoutResponse = encodeRedirectRequest(secondSPLogoutResponse)
            val secondSPResponseQueryParams = SimpleSign().signUriString(
                SAML_RESPONSE,
                encodedSecondSPLogoutResponse,
                logoutRequestRelayState)
            val logoutResponse = sendRedirectLogoutMessage(secondSPResponseQueryParams)

            useDefaultServiceProvider()
            val samlResponseDom = logoutResponse.getBindingVerifier().decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                logoutResponse.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlResponseDom).verifyLogoutResponse()
        }

        "Redirect LogoutRequest Test With Relay State - Single SP" {
            val ssoResponseDom = login(HTTP_REDIRECT)

            val logoutRequest = createDefaultLogoutRequest(HTTP_REDIRECT, ssoResponseDom)
            val encodedRequest = encodeRedirectRequest(logoutRequest)
            val queryParams = SimpleSign().signUriString(
                SAML_REQUEST,
                encodedRequest,
                EXAMPLE_RELAY_STATE)
            val response = sendRedirectLogoutMessage(queryParams)

            val samlResponseDom = response.getBindingVerifier().apply {
                isRelayStateGiven = true
            }.decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                response.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlResponseDom).verifyLogoutResponse()
        }

        "Redirect LogoutRequest Test With Relay State - Multiple SPs" {
            val ssoResponseDom = login(HTTP_REDIRECT, multipleSP = true)

            val logoutRequest = createDefaultLogoutRequest(HTTP_REDIRECT, ssoResponseDom)
            val encodedRequest = encodeRedirectRequest(logoutRequest)
            val queryParams = SimpleSign().signUriString(
                SAML_REQUEST,
                encodedRequest,
                EXAMPLE_RELAY_STATE)
            val secondSPLogoutRequest = sendRedirectLogoutMessage(queryParams)

            useDSAServiceProvider()
            val samlLogoutRequestDom = secondSPLogoutRequest.getBindingVerifier().apply {
                isSamlRequest = true
            }.decodeAndVerify()
            CoreLogoutRequestProtocolVerifier(samlLogoutRequestDom,
                secondSPLogoutRequest.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlLogoutRequestDom).verifyLogoutRequest(ssoResponseDom)

            val secondSPLogoutResponse =
                    createDefaultLogoutResponse(samlLogoutRequestDom, true)
            val encodedSecondSPLogoutResponse = encodeRedirectRequest(secondSPLogoutResponse)
            val secondSPResponseQueryParams = SimpleSign().signUriString(
                SAML_RESPONSE,
                encodedSecondSPLogoutResponse,
                logoutRequestRelayState)
            val logoutResponse = sendRedirectLogoutMessage(secondSPResponseQueryParams)

            useDefaultServiceProvider()
            val samlResponseDom = logoutResponse.getBindingVerifier().apply {
                isRelayStateGiven = true
            }.decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                logoutResponse.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlResponseDom).verifyLogoutResponse()
        }

        "Redirect LogoutRequest Test With Error Logging Out From SP2 - Multiple SPs" {
            val ssoResponseDom = login(HTTP_REDIRECT, multipleSP = true)

            val logoutRequest = createDefaultLogoutRequest(HTTP_REDIRECT, ssoResponseDom)
            val encodedRequest = encodeRedirectRequest(logoutRequest)
            val queryParams = SimpleSign().signUriString(
                SAML_REQUEST,
                encodedRequest,
                EXAMPLE_RELAY_STATE)
            val secondSPLogoutRequest = sendRedirectLogoutMessage(queryParams)

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
            val encodedSecondSPLogoutResponse = encodeRedirectRequest(secondSPLogoutResponse)
            val secondSPResponseQueryParams = SimpleSign().signUriString(
                SAML_RESPONSE,
                encodedSecondSPLogoutResponse,
                logoutRequestRelayState)
            val logoutResponse = sendRedirectLogoutMessage(secondSPResponseQueryParams)

            useDefaultServiceProvider()
            val samlResponseDom = logoutResponse.getBindingVerifier().apply {
                isRelayStateGiven = true
            }.decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                logoutResponse.determineBinding(), PARTIAL_LOGOUT).verify()
            SingleLogoutProfileVerifier(samlResponseDom).verifyLogoutResponse()
        }

        "DDF-Specific: Redirect LogoutRequest With SHA256 Signature Test - Single SP".config(
                enabled = runningDDFProfile()) {
            useDSAServiceProvider()
            val ssoResponseDom = login(HTTP_REDIRECT)

            val logoutRequest = createDefaultLogoutRequest(HTTP_REDIRECT, ssoResponseDom)
            val encodedRequest = encodeRedirectRequest(logoutRequest)
            val queryParams = SimpleSign(ALGO_ID_SIGNATURE_DSA_SHA256).signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)
            val response = sendRedirectLogoutMessage(queryParams)

            val samlResponseDom = response.getBindingVerifier().decodeAndVerify()
            CoreLogoutResponseProtocolVerifier(logoutRequest, samlResponseDom,
                    response.determineBinding()).verify()
            SingleLogoutProfileVerifier(samlResponseDom).verifyLogoutResponse()
        }
    }
}
