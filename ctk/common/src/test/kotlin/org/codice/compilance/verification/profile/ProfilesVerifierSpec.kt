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

import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.shouldThrow
import io.kotlintest.specs.StringSpec
import org.codice.compliance.Common
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_4_1_4_2_k
import org.codice.compliance.SAMLProfiles_4_1_4_2_l
import org.codice.compliance.utils.REQUESTER
import org.codice.compliance.verification.profile.ProfilesVerifier
import java.time.Instant
import java.util.UUID

@Suppress("StringLiteralDuplication")
class ProfilesVerifierSpec : StringSpec() {
    init {

        "error response with no assertions should pass" {
            Common.buildDom(createErrorResponse(withAssertion = false)).let {
                ProfilesVerifier.verifyErrorResponseAssertion(it)
            }
        }

        "error response with an assertion should fail with provided error" {
            Common.buildDom(createErrorResponse(withAssertion = true)).let {
                shouldThrow<SAMLComplianceException> {
                    ProfilesVerifier.verifyErrorResponseAssertion(it, SAMLProfiles_4_1_4_2_k)
                }.message?.apply {
                    this.shouldContain(SAMLProfiles_4_1_4_2_l.message)
                    this.shouldContain(SAMLProfiles_4_1_4_2_k.message)
                }
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
