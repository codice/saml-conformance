/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.web.slo.error

import io.kotlintest.TestCaseConfig
import io.kotlintest.provided.SLO
import io.restassured.RestAssured
import org.codice.compliance.LENIENT_ERROR_VERIFICATION
import org.codice.compliance.SAMLBindings_3_5_3_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_7_3_2_c
import org.codice.compliance.SAMLProfiles_4_4_3_5_a
import org.codice.compliance.utils.RELAY_STATE_GREATER_THAN_80_BYTES
import org.codice.compliance.utils.REQUESTER
import org.codice.compliance.utils.SLOCommon.Companion.createDefaultLogoutRequest
import org.codice.compliance.utils.SLOCommon.Companion.login
import org.codice.compliance.utils.SLOCommon.Companion.sendPostLogoutMessage
import org.codice.compliance.utils.TestCommon.Companion.signAndEncodePostRequestToString
import org.codice.compliance.utils.getBindingVerifier
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.core.CoreVerifier
import org.codice.compliance.web.BaseTest
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST

class PostSLOErrorTest : BaseTest() {
    override val defaultTestCaseConfig = TestCaseConfig(tags = setOf(SLO))

    init {
        RestAssured.useRelaxedHTTPSValidation()
        val isLenient = System.getProperty(LENIENT_ERROR_VERIFICATION) == "true"

        "Bindings 3.5.3: POST LogoutResponse Test With Relay State Greater Than 80 Bytes" {
            try {
                login(HTTP_POST)

                val logoutRequest = createDefaultLogoutRequest(HTTP_POST)
                val encodedRequest =
                        signAndEncodePostRequestToString(logoutRequest,
                                RELAY_STATE_GREATER_THAN_80_BYTES)

                val response = sendPostLogoutMessage(encodedRequest)

                if (!isLenient || !BindingVerifier.isErrorHttpStatusCode(response.statusCode)) {
                    val samlResponseDom = response.getBindingVerifier().decodeAndVerifyError()

                    CoreVerifier.verifyErrorStatusCodes(samlResponseDom,
                            SAMLBindings_3_5_3_a,
                            SAMLCore_3_7_3_2_c,
                            SAMLProfiles_4_4_3_5_a,
                            expectedStatusCode = REQUESTER)
                }
            } catch (e: SAMLComplianceException) {
                throw SAMLComplianceException.recreateExceptionWithErrorMessage(e)
            }
        }
    }
}
