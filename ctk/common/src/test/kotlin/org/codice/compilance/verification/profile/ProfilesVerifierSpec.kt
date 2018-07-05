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
package org.codice.compilance.verification.profile

import com.google.common.io.Resources
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.shouldThrow
import io.kotlintest.specs.StringSpec
import org.codice.compliance.Common
import org.codice.compliance.IMPLEMENTATION_PATH
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_4_1_4_2_a
import org.codice.compliance.SAMLProfiles_4_1_4_2_i
import org.codice.compliance.SAMLProfiles_4_1_4_2_j
import org.codice.compliance.utils.ENTITY
import org.codice.compliance.utils.REQUESTER
import org.codice.compliance.verification.profile.ProfilesVerifier
import java.time.Instant
import java.util.UUID

class ProfilesVerifierSpec : StringSpec() {
    private val correctIdpIssuer = "http://correct.idp.issuer"
    private val incorrectIdpIssuer = "incorrect/idp/issuer"

    private val createResponse = { issuer: String ->
        """
        |<s:Response
        |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
        |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
        |ID="${"a" + UUID.randomUUID().toString()}"
        |Version="2.0"
        |IssueInstant="${Instant.now()}">
        |  $issuer
        |</s:Response>
        """.trimMargin()
    }

    private val createIssuer = { format: String, value: String ->
        "<s2:Issuer Format=\"$format\">$value</s2:Issuer>"
    }

    init {
        System.setProperty(IMPLEMENTATION_PATH,
                Resources.getResource("implementation").path)

        "error response with no assertions should pass" {
            Common.buildDom(createErrorResponse(withAssertion = false)).let {
                ProfilesVerifier.verifyErrorResponseAssertion(it)
            }
        }

        "error response with an assertion should fail with provided error" {
            Common.buildDom(createErrorResponse(withAssertion = true)).let {
                shouldThrow<SAMLComplianceException> {
                    ProfilesVerifier.verifyErrorResponseAssertion(it, SAMLProfiles_4_1_4_2_i)
                }.message?.apply {
                    this.shouldContain(SAMLProfiles_4_1_4_2_j.message)
                    this.shouldContain(SAMLProfiles_4_1_4_2_i.message)
                }
            }
        }

        "response with correct issuer value and format should pass" {
            Common.buildDom(createResponse(createIssuer(ENTITY, correctIdpIssuer))).let {
                ProfilesVerifier.verifyIssuer(it, SAMLProfiles_4_1_4_2_a)
            }
        }

        "response with incorrect issuer value should fail" {
            Common.buildDom(createResponse(createIssuer(ENTITY, incorrectIdpIssuer))).let {
                shouldThrow<SAMLComplianceException> {
                    ProfilesVerifier.verifyIssuer(it, SAMLProfiles_4_1_4_2_a)
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_a.message)
            }
        }

        "response with incorrect issuer format should fail" {
            Common.buildDom(createResponse(createIssuer("wrongFormat", correctIdpIssuer))).let {
                shouldThrow<SAMLComplianceException> {
                    ProfilesVerifier.verifyIssuer(it, SAMLProfiles_4_1_4_2_a)
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_a.message)
            }
        }

        "response with multiple issuers should fail" {
            val multipleIssuers = """
            |<s2:Issuer>https://localhost:8993/services/idp/login</s2:Issuer>
            |<s2:Issuer>https://localhost:8993/services/idp/login</s2:Issuer>
           """.trimMargin()

            Common.buildDom(createResponse(multipleIssuers)).let {
                shouldThrow<SAMLComplianceException> {
                    ProfilesVerifier.verifyIssuer(it, SAMLProfiles_4_1_4_2_a)
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_a.message)
            }
        }

        "response with no issuer should fail" {
            Common.buildDom(createResponse("")).let {
                shouldThrow<SAMLComplianceException> {
                    ProfilesVerifier.verifyIssuer(it, SAMLProfiles_4_1_4_2_a)
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_a.message)
            }
        }
    }

    private fun createErrorResponse(withAssertion: Boolean): String {
        var assertion = ""
        if (withAssertion) {
            assertion = """
            |<s2:Assertion ID="${"a" + UUID.randomUUID().toString()}"
            |Version="2.0"
            |IssueInstant="${Instant.now()}">
            |  <s2:Issuer>https://localhost:8993/services/idp/login</s2:Issuer>
            |</s2:Assertion>
            """.trimMargin()
        }
        return """
            |<s:Response
            |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
            |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
            |ID="${"a" + UUID.randomUUID().toString()}"
            |Version="2.0"
            |IssueInstant="${Instant.now()}">
            |  $assertion
            |  <s:Status>
            |    <s:StatusCode Value="$REQUESTER"></s:StatusCode>
            |  </s:Status>
            |</s:Response>
           """.trimMargin()
    }
}
