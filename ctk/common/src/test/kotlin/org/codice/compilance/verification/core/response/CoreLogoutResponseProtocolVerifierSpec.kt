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
package org.codice.compilance.verification.core.response

import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.shouldThrow
import io.kotlintest.specs.StringSpec
import org.codice.compliance.Common
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_7_3_2_b
import org.codice.compliance.SAMLCore_3_7_3_2_d
import org.codice.compliance.utils.PERSISTENT_ID
import org.codice.compliance.utils.RESPONDER
import org.codice.compliance.utils.SUCCESS
import org.codice.compliance.utils.TestCommon.Companion.REQUEST_ID
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.compliance.verification.core.responses.CoreLogoutResponseProtocolVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion.VERSION_20
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import org.opensaml.saml.saml2.core.impl.LogoutRequestBuilder
import org.opensaml.saml.saml2.core.impl.NameIDBuilder
import java.time.Instant
import java.util.UUID

class CoreLogoutResponseProtocolVerifierSpec : StringSpec() {

    private val logoutRequest by lazy {
        REQUEST_ID = "a" + UUID.randomUUID().toString()

        LogoutRequestBuilder().buildObject().apply {
            issuer = IssuerBuilder().buildObject().apply { value = currentSPIssuer }
            id = REQUEST_ID
            version = VERSION_20
            issueInstant = DateTime()
            destination = "https://localhost:8993/services/idp/login"
            nameID = NameIDBuilder().buildObject().apply {
                nameQualifier = "https://localhost:8993/services/idp/login"
                spNameQualifier = currentSPIssuer
                format = PERSISTENT_ID
                value = "admin"
            }
        }
    }

    init {
        "logout response with correct second-level status code should pass" {
            Common.buildDom(createLogoutResponse(SUCCESS)).let {
                CoreLogoutResponseProtocolVerifier(logoutRequest, it, HTTP_POST, SUCCESS).verify()
            }
        }

        "logout response with incorrect second-level status code should fail" {
            Common.buildDom(createLogoutResponse(RESPONDER)).let {
                shouldThrow<SAMLComplianceException> {
                    CoreLogoutResponseProtocolVerifier(logoutRequest, it, HTTP_POST, SUCCESS)
                        .verify()
                }.apply {
                    this.message?.shouldContain(SAMLCore_3_7_3_2_b.message)
                    this.message?.shouldContain(SAMLCore_3_7_3_2_d.message)
                }
            }
        }
    }

    private fun createLogoutResponse(secondStatusCodeValue: String): String {
        return """
            |<s:LogoutResponse
            |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
            |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
            |ID="${"a" + UUID.randomUUID().toString()}"
            |Version="2.0"
            |IssueInstant="${Instant.now()}">
            |  <s:Status>
            |    <s:StatusCode Value="$SUCCESS">
            |      <s:StatusCode Value="$secondStatusCodeValue"/>
            |    </s:StatusCode>
            |  </s:Status>
            |</s:LogoutResponse>
           """.trimMargin()
    }
}
