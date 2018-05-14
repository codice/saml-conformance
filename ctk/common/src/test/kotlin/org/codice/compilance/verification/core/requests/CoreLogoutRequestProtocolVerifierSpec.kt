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
package org.codice.compilance.verification.core.requests

import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.shouldThrow
import io.kotlintest.specs.StringSpec
import org.codice.compliance.Common
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_1_3_2_a
import org.codice.compliance.SAMLCore_1_3_3_a
import org.codice.compliance.SAMLCore_3_7_1_a
import org.codice.compliance.verification.core.requests.CoreLogoutRequestProtocolVerifier
import java.time.Instant
import java.util.UUID

class CoreLogoutRequestProtocolVerifierSpec : StringSpec() {
    init {
        val now = Instant.now()
        val response = { attribute: String ->
            """
            |<s:LogoutRequest
            |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
            |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
            |ID="${UUID.randomUUID().toString().replace("-", "")}"
            |Version="2.0"
            |$attribute
            |IssueInstant="$now">
            |  <s2:Issuer>https://localhost:8993/services/idp/login</s2:Issuer>
            |  <s2:NameID
            |  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">admin</s2:NameID>
            |</s:LogoutRequest>
           """.trimMargin()
        }

        "response with correct reason should pass" {
            Common.buildDom(response("Reason=\"http://correct.reason/uri\"")).let {
                CoreLogoutRequestProtocolVerifier(it).verify()
            }
        }

        "response with incorrect reason (relative URI) should fail with SAMLCore_3_7_1_a" {
            val message = Common.buildDom(response("Reason=\"/incorrect/reason/uri\"")).let {
                shouldThrow<SAMLComplianceException> {
                    CoreLogoutRequestProtocolVerifier(it).verify()
                }.message
            }
            message?.shouldContain(SAMLCore_1_3_2_a.message)
            message?.shouldContain(SAMLCore_3_7_1_a.message)
        }

        "response with correct NotOnOrAfter should pass" {
            Common.buildDom(response("NotOnOrAfter=\"2018-05-01T13:15:30Z\"")).let {
                CoreLogoutRequestProtocolVerifier(it).verify()
            }
        }

        "response with incorrect NotOnOrAfter (non-UTC) should fail with SAMLCore_3_7_1_a" {
            Common.buildDom(response("NotOnOrAfter=\"2018-05-01T06:15:30-07:00\"")).let {
                shouldThrow<SAMLComplianceException> {
                    CoreLogoutRequestProtocolVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_1_3_3_a.message)
            }
        }
    }
}
