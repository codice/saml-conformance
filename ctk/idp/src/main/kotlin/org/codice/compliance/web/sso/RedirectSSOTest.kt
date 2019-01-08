/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.web.sso

import io.kotlintest.TestCaseConfig
import io.kotlintest.provided.SSO
import io.restassured.RestAssured
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.apache.wss4j.common.saml.builder.SAML2Constants
import org.codice.compliance.Common.Companion.runningDDFProfile
import org.codice.compliance.saml.plugin.IdpSSOResponder
import org.codice.compliance.utils.EXAMPLE_RELAY_STATE
import org.codice.compliance.utils.SSOCommon.Companion.createDefaultAuthnRequest
import org.codice.compliance.utils.SSOCommon.Companion.sendRedirectAuthnRequest
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.compliance.utils.TestCommon.Companion.encodeRedirectRequest
import org.codice.compliance.utils.TestCommon.Companion.getImplementation
import org.codice.compliance.utils.TestCommon.Companion.useDSAServiceProvider
import org.codice.compliance.utils.ddfAuthnContextList
import org.codice.compliance.utils.getBindingVerifier
import org.codice.compliance.utils.sign.SimpleSign
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.core.responses.CoreAuthnRequestProtocolVerifier
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import org.codice.compliance.web.BaseTest
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder
import org.opensaml.saml.saml2.core.impl.RequestedAuthnContextBuilder
import org.opensaml.xmlsec.signature.support.SignatureConstants.ALGO_ID_SIGNATURE_DSA_SHA256

class RedirectSSOTest : BaseTest() {
    override val defaultTestCaseConfig = TestCaseConfig(tags = setOf(SSO))

    init {
        RestAssured.useRelaxedHTTPSValidation()

        "Redirect AuthnRequest Test" {
            val authnRequest = createDefaultAuthnRequest(HTTP_REDIRECT)
            val encodedRequest = encodeRedirectRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)
            val response = sendRedirectAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForRedirectRequest(
                            response)
            val samlResponseDom = finalHttpResponse.getBindingVerifier().decodeAndVerify()

            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        "Redirect AuthnRequest With Relay State Test" {
            val authnRequest = createDefaultAuthnRequest(HTTP_REDIRECT)
            val encodedRequest = encodeRedirectRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    EXAMPLE_RELAY_STATE)

            val response = sendRedirectAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForRedirectRequest(
                            response)
            val samlResponseDom =
                    finalHttpResponse.getBindingVerifier().apply {
                        isRelayStateGiven = true
                    }.decodeAndVerify()

            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        "Redirect AuthnRequest Without ACS Url or ACS Index Test" {
            val authnRequest = createDefaultAuthnRequest(HTTP_REDIRECT).apply {
                assertionConsumerServiceURL = null
            }
            val encodedRequest = encodeRedirectRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)

            val response = sendRedirectAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForRedirectRequest(
                            response)
            val samlResponseDom = finalHttpResponse.getBindingVerifier().decodeAndVerify()

            // Main goal of this test is to verify the ACS in verifyAssertionConsumerService
            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        "Bindings 3.4.4.1: Redirect AuthnRequest Using DSA1 Signature Algorithm" {
            useDSAServiceProvider()
            val authnRequest = createDefaultAuthnRequest(HTTP_REDIRECT)
            val encodedRequest = encodeRedirectRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)

            val response = sendRedirectAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForRedirectRequest(
                            response)
            val samlResponseDom = finalHttpResponse.getBindingVerifier().decodeAndVerify()

            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        "Redirect AuthnRequest With Email NameID Format Test".config(enabled = false) {
            val authnRequest = createDefaultAuthnRequest(HTTP_REDIRECT).apply {
                nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
                    format = SAML2Constants.NAMEID_FORMAT_EMAIL_ADDRESS
                    spNameQualifier = currentSPIssuer
                }
            }
            val encodedRequest = encodeRedirectRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)

            val response = sendRedirectAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForRedirectRequest(
                            response)
            val samlResponseDom = finalHttpResponse.getBindingVerifier().decodeAndVerify()

            // Main goal of this test is to do the NameIDPolicy verification in
            // CoreAuthnRequestProtocolVerifier
            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        "DDF-Specific: Redirect AuthnRequest Using DSA SHA256 for Signing Test".config(
                enabled = runningDDFProfile()) {
            useDSAServiceProvider()
            val authnRequest = createDefaultAuthnRequest(HTTP_REDIRECT)
            val encodedRequest = encodeRedirectRequest(authnRequest)
            val queryParams = SimpleSign(ALGO_ID_SIGNATURE_DSA_SHA256).signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)
            val response = sendRedirectAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForRedirectRequest(
                            response)
            val samlResponseDom = finalHttpResponse.getBindingVerifier().decodeAndVerify()

            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
            }
            SingleSignOnProfileVerifier(samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }

        "DDF-Specific: Redirect AuthnRequest With AuthnContext Test".config(
                enabled = runningDDFProfile()) {
            val reqAuthnContextClassRefs = ddfAuthnContextList
                    .map {
                        AuthnContextClassRefBuilder().buildObject().apply {
                            authnContextClassRef = it
                        }
                    }
                    .toList()

            val authnRequest = createDefaultAuthnRequest(HTTP_REDIRECT).apply {
                requestedAuthnContext = RequestedAuthnContextBuilder().buildObject().apply {
                    authnContextClassRefs.addAll(reqAuthnContextClassRefs)
                }
            }

            val encodedRequest = encodeRedirectRequest(authnRequest)
            val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)

            val response = sendRedirectAuthnRequest(queryParams)
            BindingVerifier.verifyHttpStatusCode(response.statusCode)

            val finalHttpResponse =
                    getImplementation(IdpSSOResponder::class).getResponseForRedirectRequest(
                            response)
            val samlResponseDom = finalHttpResponse.getBindingVerifier().decodeAndVerify()

            CoreAuthnRequestProtocolVerifier(authnRequest, samlResponseDom).apply {
                verify()
                verifyAssertionConsumerService(finalHttpResponse)
                verifyAuthnContextClassRef()
            }
            SingleSignOnProfileVerifier(samlResponseDom).apply {
                verify()
                verifyBinding(finalHttpResponse)
            }
        }
    }
}
