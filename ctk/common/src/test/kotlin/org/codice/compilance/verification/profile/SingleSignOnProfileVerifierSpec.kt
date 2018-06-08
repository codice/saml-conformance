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
import org.codice.compliance.utils.SUCCESS
import org.codice.compliance.utils.TestCommon.Companion.REQUEST_ID
import org.codice.compliance.verification.core.CoreVerifier
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import org.w3c.dom.Node
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

        "unsigned response with encrypted assertion and correct issuer should pass" {
            Common.buildDom(createResponseWithEncryptedAssertion(correctIdpIssuer)).let {
                CoreVerifierTest(it).verify()
                SingleSignOnProfileVerifier(it).verify()
            }
        }

        "unsigned response with encrypted assertion and incorrect issuer should fail" {
            Common.buildDom(createResponseWithEncryptedAssertion(incorrectIdpIssuer)).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_b.message)
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

    private fun createResponseWithEncryptedAssertion(issuer: String): String {
        return """
            |<s:Response $responseParams>
            |  <s2:Issuer>$issuer</s2:Issuer>
            |  <s:Status>
            |    <s:StatusCode Value="$SUCCESS"/>
            |  </s:Status>
            |  <s2:EncryptedAssertion>
            |    <xenc:EncryptedData Type="http://www.w3.org/2001/04/xmlenc#Element">
            |      <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#aes128-cbc"/>
            |      <dsig:KeyInfo>
            |        <xenc:EncryptedKey>
            |          <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
            |          <xenc:CipherData>
            |            <xenc:CipherValue>
            |              B9y4kamLX2fRIfKtk10v1zeLq/eMz/FU09Tp1ezCMoBErG9wqamEBip7bvFTuJGWKuSRIx
            |              Bt0+4cFR716M98C1ni2j4ddR9ZgiOr/LwgXoVGkTE3ud3n1+y/y3h8G44dNouWGAITR7/l
            |              axE+3JohUqea7gBfarL69Wk5eGoR/jcjaA1vpKxqd2+WAcy/W4EOSVQpLyDC86a9MZ41B/
            |              /t/RbWNv86PD3qR/lS1sUwiMwtB3SUB68wPNECLH83ZVZuWYsQXIj/5UDbznA85hStudMC
            |              U8GaiTUryqk6RAT3VY463aQKyuZx/P6rUkAtlznFcqog/saBld1hJJeVYmxQSg==
            |            </xenc:CipherValue>
            |          </xenc:CipherData>
            |        </xenc:EncryptedKey>
            |      </dsig:KeyInfo>
            |      <xenc:CipherData>
            |        <xenc:CipherValue>
            |          2/2pEg+WXDMwIt9EhFEfjaMPGP0Pwi0WhM7YKzsJdyVSe8wDrxp7mnDDBv+R5nK2SGoczQznLf
            |          9dNgMMujHGm6q61l7IjFnCKDFNJux5Y0YvpLR7wWMesNl3ry9IG5gix2P8VkWD/gscFcWaxTKx
            |          91Hj3o30Smfr0k2GwsCdQY4k1tjrXPJFhGgp0Idq9BMGd0MFjmi2xYh5Dw3tj6qbkkFQrMJh5/
            |          8Pnddo3cg46LQpa6XF64WIhV6xSD35nQXqlMpdBX+GcnCIcwTXfq8dahLziSwg6jRN5pkg0KuF
            |          cvIaBktTQO7S7vkS1ErgIqwOilmS6PQUoxOsgrwuK3ogQpR3FwmHr7Tb9a6NheRen44MlZwSJx
            |          xpCQv1g5da9QBn1EH8/BNdr27LM7XnyP2r+Y2XnsKEZrLmL8ySbKjzWNLbWI7RRiIzarBA5Bwv
            |          zd1udy6btL1LXOB0eO/z2E/gFLjvbVHw/uE6wj3fGsD4ouY5jb+U1HgEEATtF+NksMBT0qJSL8
            |          6uLjA9/wEDD9T1DdrGWCvg/JAYlkZmfXx/Rl6V82+RpFG8BgPfsXLWOid5UQLeXDJLwEasgCKc
            |          ZNg7LmK5MGCWzzKm30KiXufbHquH8P93xdk/ttwfJwKNGmaxGQ/54B3ONqBT2Z7KkOAQmWY1P1
            |          1lx4vX3j3pPUF82ItCTLOPyvwEDVwwUNgeI3HP8G1nOVf1slGK/PixIvU9FOwA5WKck4H6KfK5
            |          J/c/7MtHVegXjjdxy48B7iBfRKSa9b/Uy+irL2CLFRFWFaHP4z5WWg9Y3ATFa3+h0NimYC/TnA
            |          Teen6celecaYaBaW7ORSxwYyxV2FWYlQqLwO238f7emT+wOwGVKYxztN9LzTRKHFdhNN7Un/FV
            |          lvphjUcz
            |        </xenc:CipherValue>
            |      </xenc:CipherData>
            |    </xenc:EncryptedData>
            |  </s2:EncryptedAssertion>
            |</s:Response>
           """.trimMargin()
    }
}

private class CoreVerifierTest(node: Node) : CoreVerifier(node)
