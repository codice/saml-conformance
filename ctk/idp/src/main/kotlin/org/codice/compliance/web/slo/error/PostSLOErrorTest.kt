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
import org.codice.compliance.LENIENT_ERROR_VERIFICATION
import org.codice.compliance.SAMLBindings_3_5_3_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.utils.TestCommon.Companion.RELAY_STATE_GREATER_THAN_80_BYTES
import org.codice.compliance.utils.TestCommon.Companion.REQUESTER
import org.codice.compliance.utils.TestCommon.Companion.createDefaultLogoutRequest
import org.codice.compliance.utils.TestCommon.Companion.loginAndGetCookies
import org.codice.compliance.utils.TestCommon.Companion.sendPostLogoutMessage
import org.codice.compliance.utils.TestCommon.Companion.signAndEncodePostRequestToString
import org.codice.compliance.utils.getBindingVerifier
import org.codice.compliance.verification.binding.BindingVerifier.Companion.isErrorHttpStatusCode
import org.codice.compliance.verification.core.CoreVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST

class PostSLOErrorTest : StringSpec() {

    init {
        RestAssured.useRelaxedHTTPSValidation()
        val isLenient = System.getProperty(LENIENT_ERROR_VERIFICATION) == "true"

        "Bindings 3.5.3: POST LogoutResponse Test With Relay State Greater Than 80 Bytes" {
            try {
                val cookies = loginAndGetCookies(HTTP_POST)

                val logoutRequest = createDefaultLogoutRequest(HTTP_POST)
                val encodedRequest =
                    signAndEncodePostRequestToString(logoutRequest,
                        RELAY_STATE_GREATER_THAN_80_BYTES)

                val response = sendPostLogoutMessage(encodedRequest, cookies)

                if (!isLenient || !isErrorHttpStatusCode(response.statusCode)) {
                    val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                    CoreVerifier.verifyErrorStatusCode(samlResponseDom,
                        samlErrorCode = SAMLBindings_3_5_3_a,
                        expectedStatusCode = REQUESTER)
                }
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }
    }
}
