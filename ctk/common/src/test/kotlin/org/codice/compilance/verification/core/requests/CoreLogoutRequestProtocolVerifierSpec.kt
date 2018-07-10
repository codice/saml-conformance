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
import org.codice.compliance.SAMLCore_3_7_3_2_e
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.verification.core.requests.CoreLogoutRequestProtocolVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT
import java.time.Instant
import java.util.UUID

class CoreLogoutRequestProtocolVerifierSpec : StringSpec() {
    @Suppress("MagicNumber")
    private val correctNotOnOrAfter = Instant.now().plusMillis(300000).toString()

    init {
        "logout request with correct reason should pass" {
            NodeDecorator(Common.buildDom(
                    createLogoutRequest("""Reason="http://correct.reason/uri"""",
                            correctNotOnOrAfter))).let {
                CoreLogoutRequestProtocolVerifier(it, HTTP_REDIRECT).verify()
            }
        }

        "logout request with incorrect reason (relative URI) should fail with SAMLCore_3_7_1_a" {
            NodeDecorator(Common.buildDom(
                    createLogoutRequest("""Reason="/incorrect/reason/uri"""",
                            correctNotOnOrAfter))).let {
                shouldThrow<SAMLComplianceException> {
                    CoreLogoutRequestProtocolVerifier(it, HTTP_POST).verify()
                }.message
            }.apply {
                this?.shouldContain(SAMLCore_1_3_2_a.message)
                this?.shouldContain(SAMLCore_3_7_1_a.message)
            }
        }

        "logout request with correct NotOnOrAfter should pass" {
            NodeDecorator(Common.buildDom(
                    createLogoutRequest("", "2018-05-01T13:15:30Z"))).let {
                CoreLogoutRequestProtocolVerifier(it, HTTP_REDIRECT).verify()
            }
        }

        "logout request with incorrect NotOnOrAfter (non-UTC) should fail with SAMLCore_3_7_1_a" {
            NodeDecorator(Common.buildDom(
                    createLogoutRequest("", "2018-05-01T06:15:30-07:00"))).let {
                shouldThrow<SAMLComplianceException> {
                    CoreLogoutRequestProtocolVerifier(it, HTTP_POST).verify()
                }.message?.shouldContain(SAMLCore_1_3_3_a.message)
            }
        }

        "logout request with no NotOnOrAfter should fail with SAMLCore_3_7_3_2_e" {
            NodeDecorator(Common.buildDom(createLogoutRequest("", null))).let {
                shouldThrow<SAMLComplianceException> {
                    CoreLogoutRequestProtocolVerifier(it, HTTP_POST).verify()
                }.message?.shouldContain(SAMLCore_3_7_3_2_e.message)
            }
        }
    }

    private fun createLogoutRequest(attribute: String = "", notOnOrAfter: String?): String {
        var additionalAttribute = attribute
        if (notOnOrAfter != null) {
            additionalAttribute = "$attribute NotOnOrAfter=\"$notOnOrAfter\""
        }
        return """
            |<s:LogoutRequest
            |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
            |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
            |ID="${"a" + UUID.randomUUID().toString()}"
            |Version="2.0"
            |$additionalAttribute
            |IssueInstant="${Instant.now()}">
            |  <s2:Issuer>https://localhost:8993/services/idp/login</s2:Issuer>
            |  <s2:NameID
            |  Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">admin</s2:NameID>
            |</s:LogoutRequest>
           """.trimMargin()
    }
}
