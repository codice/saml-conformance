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
package org.codice.compliance.web.slo.error

import com.jayway.restassured.RestAssured
import io.kotlintest.specs.StringSpec
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.codice.compliance.LENIENT_ERROR_VERIFICATION
import org.codice.compliance.SAMLBindings_3_4_3_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_7_3_2_a
import org.codice.compliance.SAMLCore_3_7_3_2_c
import org.codice.compliance.utils.TestCommon.Companion.RELAY_STATE_GREATER_THAN_80_BYTES
import org.codice.compliance.utils.TestCommon.Companion.REQUESTER
import org.codice.compliance.utils.TestCommon.Companion.createDefaultLogoutRequest
import org.codice.compliance.utils.TestCommon.Companion.encodeRedirectRequest
import org.codice.compliance.utils.TestCommon.Companion.loginAndGetCookies
import org.codice.compliance.utils.TestCommon.Companion.sendRedirectLogoutMessage
import org.codice.compliance.utils.getBindingVerifier
import org.codice.compliance.utils.sign.SimpleSign
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.core.CoreVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT

class RedirectSLOErrorTest : StringSpec() {

    init {
        RestAssured.useRelaxedHTTPSValidation()
        val isLenient = System.getProperty(LENIENT_ERROR_VERIFICATION) == "true"

        "Bindings 3.4.3: Redirect LogoutResponse Test With Relay State Greater Than 80 Bytes" {
            try {
                val cookies = loginAndGetCookies(HTTP_REDIRECT)

                val logoutRequest = createDefaultLogoutRequest(HTTP_REDIRECT)
                val encodedRequest = encodeRedirectRequest(logoutRequest)
                val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    RELAY_STATE_GREATER_THAN_80_BYTES)

                val response = sendRedirectLogoutMessage(queryParams, cookies)

                if (!isLenient || !BindingVerifier.isErrorHttpStatusCode(response.statusCode)) {
                    val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                    CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                        SAMLBindings_3_4_3_a,
                        SAMLCore_3_7_3_2_c,
                        expectedStatusCode = REQUESTER)
                }
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }

        "Core 3.7.3.2: Redirect LogoutResponse Test Without Logging In" {
            try {
                val logoutRequest = createDefaultLogoutRequest(HTTP_REDIRECT)
                val encodedRequest = encodeRedirectRequest(logoutRequest)
                val queryParams = SimpleSign().signUriString(
                    SAML_REQUEST,
                    encodedRequest,
                    null)
                val response = sendRedirectLogoutMessage(queryParams)

                if (!isLenient || !BindingVerifier.isErrorHttpStatusCode(response.statusCode)) {
                    val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                    CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                        SAMLCore_3_7_3_2_a,
                        SAMLCore_3_7_3_2_c,
                        expectedStatusCode = REQUESTER)
                }
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }
    }
}
