/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.web.sso.error

import io.kotlintest.TestCaseConfig
import io.kotlintest.provided.SSO
import io.restassured.RestAssured
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.codice.compliance.LENIENT_ERROR_VERIFICATION
import org.codice.compliance.SAMLBindings_3_4_3_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_2_1_e
import org.codice.compliance.SAMLProfiles_4_1_4_1_a
import org.codice.compliance.SAMLProfiles_4_1_4_1_b
import org.codice.compliance.debugPrettyPrintXml
import org.codice.compliance.saml.plugin.IdpSSOResponder
import org.codice.compliance.utils.INCORRECT_DESTINATION
import org.codice.compliance.utils.RELAY_STATE_GREATER_THAN_80_BYTES
import org.codice.compliance.utils.REQUESTER
import org.codice.compliance.utils.SSOCommon.Companion.createDefaultAuthnRequest
import org.codice.compliance.utils.SSOCommon.Companion.sendRedirectAuthnRequest
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.encodeRedirectRequest
import org.codice.compliance.utils.TestCommon.Companion.samlObjectToString
import org.codice.compliance.utils.getBindingVerifier
import org.codice.compliance.utils.sign.SimpleSign
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.core.CoreVerifier
import org.codice.compliance.verification.profile.ProfilesVerifier
import org.codice.compliance.web.BaseTest
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT
import org.codice.security.sign.Encoder.encodeRedirectMessage
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.NameIDBuilder
import org.opensaml.saml.saml2.core.impl.SubjectBuilder

class RedirectSSOErrorTest : BaseTest() {
    override val defaultTestCaseConfig = TestCaseConfig(tags = setOf(SSO))

    init {
        RestAssured.useRelaxedHTTPSValidation()
        val isLenient = System.getProperty(LENIENT_ERROR_VERIFICATION) == "true"

        "Bindings 3.4.3: Redirect AuthnRequest With Relay State Greater Than 80 Bytes Test" {
            try {
                val authnRequest =
                    createDefaultAuthnRequest(HTTP_REDIRECT)
                val encodedRequest = encodeRedirectRequest(authnRequest)
                val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    RELAY_STATE_GREATER_THAN_80_BYTES)
                val response = sendRedirectAuthnRequest(queryParams)

                if (!isLenient || !BindingVerifier.isErrorHttpStatusCode(response.statusCode)) {
                    val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                    CoreVerifier.verifyErrorStatusCodes(samlResponseDom,
                        SAMLBindings_3_4_3_a,
                        expectedStatusCode = REQUESTER)
                }
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }

        "Bindings 3.4.3: Redirect Incomplete AuthnRequest In URL Query Test" {
            try {
                val authnRequest =
                    createDefaultAuthnRequest(HTTP_REDIRECT)

                val authnRequestString = samlObjectToString(authnRequest)
                authnRequestString.debugPrettyPrintXml(SAML_REQUEST)
                val encodedRequest = encodeRedirectMessage(
                        authnRequestString.substring(0, authnRequestString.length / 2))

                val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)

                val response = sendRedirectAuthnRequest(queryParams)

                if (!isLenient || !BindingVerifier.isErrorHttpStatusCode(response.statusCode)) {
                    val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                    CoreVerifier.verifyErrorStatusCodes(samlResponseDom,
                        SAMLBindings_3_4_3_a,
                        expectedStatusCode = REQUESTER)
                    ProfilesVerifier.verifyErrorResponseAssertion(samlResponseDom)
                }
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }

        "Profiles 4.1.4.1: Empty Redirect AuthnRequest Test" {
            try {
                val authnRequest = AuthnRequestBuilder().buildObject()
                val encodedRequest = encodeRedirectRequest(authnRequest)
                val queryParams = mapOf(SAML_REQUEST to encodedRequest)
                val response = sendRedirectAuthnRequest(queryParams)

                if (!isLenient || !BindingVerifier.isErrorHttpStatusCode(response.statusCode)) {
                    val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                    CoreVerifier.verifyErrorStatusCodes(samlResponseDom,
                        SAMLProfiles_4_1_4_1_a,
                        expectedStatusCode = REQUESTER)
                    ProfilesVerifier.verifyErrorResponseAssertion(samlResponseDom)
                }
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }

        "Profiles 4.1.4.1: Redirect AuthnRequest With Subject Containing an Invalid Name ID Test" {
                try {
                    val authnRequest =
                        createDefaultAuthnRequest(HTTP_REDIRECT).apply {
                            subject = SubjectBuilder().buildObject().apply {
                                nameID = NameIDBuilder().buildObject().apply {
                                    value = "UNKNOWN NAME ID VALUE"
                                }
                            }
                        }
                    val encodedRequest = encodeRedirectRequest(authnRequest)
                    val queryParams = SimpleSign().signUriString(
                        SAML_REQUEST,
                        encodedRequest,
                        null)
                    val response = sendRedirectAuthnRequest(queryParams)
                    BindingVerifier.verifyHttpStatusCode(response.statusCode)

                    val finalHttpResponse = TestCommon.getImplementation(IdpSSOResponder::class)
                            .getResponseForRedirectRequest(response)

                    if (!isLenient ||
                            !BindingVerifier.isErrorHttpStatusCode(finalHttpResponse.statusCode)) {
                        val samlResponseDom =
                                finalHttpResponse.getBindingVerifier().decodeAndVerifyError()

                        CoreVerifier.verifyErrorStatusCodes(samlResponseDom,
                            SAMLProfiles_4_1_4_1_b,
                            expectedStatusCode = REQUESTER)
                        ProfilesVerifier
                            .verifyErrorResponseAssertion(samlResponseDom, SAMLProfiles_4_1_4_1_b)
                    }
                } catch (e: SAMLComplianceException) {
                    throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
                }
            }

        "Core 3.2.1: Redirect AuthnRequest With Non-Matching Destination" {
            try {
                val authnRequest =
                    createDefaultAuthnRequest(HTTP_REDIRECT).apply {
                        destination = INCORRECT_DESTINATION
                    }
                val encodedRequest = encodeRedirectRequest(authnRequest)
                val queryParams =
                    SimpleSign()
                        .signUriString(SAML_REQUEST, encodedRequest, null)
                val response = sendRedirectAuthnRequest(queryParams)

                if (!isLenient || !BindingVerifier.isErrorHttpStatusCode(response.statusCode)) {
                    val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                    CoreVerifier.verifyErrorStatusCodes(samlResponseDom,
                        SAMLCore_3_2_1_e,
                        expectedStatusCode = REQUESTER)
                    ProfilesVerifier.verifyErrorResponseAssertion(samlResponseDom)
                }
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }
    }
}
