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
import org.codice.compliance.SAMLProfiles_4_1_4_2_b
import org.codice.compliance.SAMLProfiles_4_1_4_2_c
import org.codice.compliance.SAMLProfiles_4_1_4_2_d
import org.codice.compliance.TEST_SP_METADATA_PROPERTY
import org.codice.compliance.utils.BEARER
import org.codice.compliance.utils.ENTITY
import org.codice.compliance.utils.TestCommon.Companion.REQUEST_ID
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import java.time.Instant
import java.util.UUID

@Suppress("StringLiteralDuplication")
class SingleSignOnProfileVerifierSpec : StringSpec() {
    private val correctIdpIssuer = "http://correct.idp.issuer"
    private val incorrectIdpIssuer = "incorrect/idp/issuer"

    private val responseParams = """
        |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
        |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
        |xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        |xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
        |xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"
        |ID="${"a" + UUID.randomUUID().toString()}"
        |Version="2.0"
        |IssueInstant="${Instant.now()}"
        """.trimMargin()

    private val createIssuer = { format: String, value: String ->
        "<s2:Issuer Format=\"$format\">$value</s2:Issuer>"
    }

    init {
        REQUEST_ID = "a6611f9cc-a8ba-46a6-b2ce-24dd8"
        System.setProperty(IMPLEMENTATION_PATH,
            Resources.getResource("implementation").path)
        System.setProperty(TEST_SP_METADATA_PROPERTY,
            Resources.getResource("test-sp-metadata.xml").path)

        // Issuer Tests
        "unsigned response with no issuer on response element should pass" {
            Common.buildDom(createResponse(false, "")).let {
                SingleSignOnProfileVerifier(it).verify()
            }
        }

        "signed response with no issuer on response element should fail" {
            Common.buildDom(createResponse(true, "")).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_a.message)
            }
        }

        "signed response with correct issuer value and format should pass" {
            Common.buildDom(createResponse(true,
                createIssuer(ENTITY, correctIdpIssuer))).let {
                SingleSignOnProfileVerifier(it).verify()
            }
        }

        "signed response with incorrect issuer value should fail" {
            Common.buildDom(createResponse(true,
                createIssuer(ENTITY, incorrectIdpIssuer))).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_b.message)
            }
        }

        "signed response with incorrect issuer format should fail" {
            Common.buildDom(createResponse(true,
                createIssuer("wrongFormat", correctIdpIssuer))).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_c.message)
            }
        }

        "signed response with multiple issuers should fail" {
            val multipleIssuers = """
            |<s2:Issuer>https://localhost:8993/services/idp/login</s2:Issuer>
            |<s2:Issuer>https://localhost:8993/services/idp/login</s2:Issuer>
           """.trimMargin()

            Common.buildDom(createResponse(true, multipleIssuers)).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_a.message)
            }
        }

        "response with incorrect assertion issuer value should fail" {
            Common.buildDom(createResponse(false, assertionIssuer = "wrong")).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_b.message)
            }
        }

        "response with no assertion should fail" {
            val noAssertionResponse = "<s:Response $responseParams/>"
            Common.buildDom(noAssertionResponse).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_d.message)
            }
        }
    }

    private fun createResponse(isSigned: Boolean = false,
        issuer: String = "<s2:Issuer>$correctIdpIssuer</s2:Issuer>",
        assertionIssuer: String = correctIdpIssuer,
        subjConf: String = createBearerSubjConf()): String {
        val signature = if (isSigned) "<ds:Signature/>" else ""
        return """
            |<s:Response $responseParams>
            |  $issuer
            |  $signature
            |  <s2:Assertion>
            |    <s2:Issuer>$assertionIssuer</s2:Issuer>
            |    <s2:Subject>
            |      $subjConf
            |    </s2:Subject>
            |    <s2:AuthnStatement SessionIndex="0"/>
            |    <s2:Conditions>
            |      <s2:AudienceRestriction>
            |        <s2:Audience>https://samlhost:8993/services/saml</s2:Audience>
            |      </s2:AudienceRestriction>
            |    </s2:Conditions>
            |  </s2:Assertion>
            |</s:Response>
           """.trimMargin()
    }

    private fun createBearerSubjConf(recipient: String = "Recipient=\"http://correct.uri\"",
        notOnOrAfter: String = "NotOnOrAfter=\"${Instant.now()}\"",
        inResponseTo: String = "InResponseTo=\"$REQUEST_ID\""): String {
        return """
            |<s2:SubjectConfirmation Method="$BEARER">
            |  <s2:SubjectConfirmationData
            |  $recipient
            |  $notOnOrAfter
            |  $inResponseTo/>
            |</s2:SubjectConfirmation>
            """.trimMargin()
    }
}
