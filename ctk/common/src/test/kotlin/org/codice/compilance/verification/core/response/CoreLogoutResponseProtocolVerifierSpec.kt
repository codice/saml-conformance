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
import org.codice.compliance.utils.NodeDecorator
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
            NodeDecorator(Common.buildDom(createLogoutResponse(SUCCESS))).let {
                CoreLogoutResponseProtocolVerifier(logoutRequest, it, HTTP_POST, SUCCESS).verify()
            }
        }

        "logout response with incorrect second-level status code should fail" {
            NodeDecorator(Common.buildDom(createLogoutResponse(RESPONDER))).let {
                shouldThrow<SAMLComplianceException> {
                    CoreLogoutResponseProtocolVerifier(logoutRequest, it, HTTP_POST, SUCCESS)
                            .verify()
                }.message?.apply {
                    shouldContain(SAMLCore_3_7_3_2_b.message)
                    shouldContain(SAMLCore_3_7_3_2_d.message)
                }
            }
        }

        "logout response with no second-level status code when expected should fail" {
            NodeDecorator(Common.buildDom(createLogoutResponse(null))).let {
                shouldThrow<SAMLComplianceException> {
                    CoreLogoutResponseProtocolVerifier(logoutRequest, it, HTTP_POST, SUCCESS)
                            .verify()
                }.message?.apply {
                    shouldContain(SAMLCore_3_7_3_2_b.message)
                    shouldContain(SAMLCore_3_7_3_2_d.message)
                }
            }
        }

        "logout response with a second-level status code when not expecting one should pass" {
            NodeDecorator(Common.buildDom(createLogoutResponse(SUCCESS))).let {
                CoreLogoutResponseProtocolVerifier(logoutRequest, it, HTTP_POST).verify()
            }
        }
    }

    private fun createLogoutResponse(secondStatusCodeValue: String?): String {
        var secondStatusCode = ""
        if (secondStatusCodeValue != null) {
            secondStatusCode = "<s:StatusCode Value=\"$secondStatusCodeValue\"/>"
        }

        return """
            |<s:LogoutResponse
            |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
            |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
            |ID="${"a" + UUID.randomUUID().toString()}"
            |Version="2.0"
            |IssueInstant="${Instant.now()}">
            |  <s:Status>
            |    <s:StatusCode Value="$SUCCESS">
            |      $secondStatusCode
            |    </s:StatusCode>
            |  </s:Status>
            |</s:LogoutResponse>
           """.trimMargin()
    }
}
