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
import org.codice.compliance.TEST_SP_METADATA_PROPERTY
import org.codice.compliance.utils.BEARER
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.utils.SUCCESS
import org.codice.compliance.utils.TestCommon.Companion.REQUEST_ID
import org.codice.compliance.verification.core.CoreVerifier
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

    private val correctEncryptedResponse =
            """
            |<s:Response $responseParams>
            |  <s2:Issuer>$correctIdpIssuer</s2:Issuer>
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
            |              ElVqbJ9ntFWOMvo4gg4JrRPdmI8Z805PdB3hlCIlbK54cI8aG0rT83jRmnu/a8F3l/fZAANU
            |              j7tnhKr4z67c0/cfaRL65w+DMFq/9s55CT0pkGZlqx+F66xHbBR/ZQJ+8mP6kgZ4i9dWORee
            |              PakoisaaabmVT3gg8Fki21HldE1hEEPgCjr8Np33OVGlYFV+0QB/vsV4SiqIL/zYceSBBOLV
            |              S8qXtr9lxc/3n0etFkcs4BnjqBDmZNMxYQqxo1dlMv9BMXGZR4rjJe9lQ1BP/5r/1Q9RbQSF
            |              87qKGK66w8HtZE6T7QSMIM00kkoutVWsHdo0svxyw8t62EREi0AdBA==
            |            </xenc:CipherValue>
            |          </xenc:CipherData>
            |        </xenc:EncryptedKey>
            |      </dsig:KeyInfo>
            |      <xenc:CipherData>
            |        <xenc:CipherValue>
            |          U5xOoBN4Fg/ZVr1Eg+1SHIrLe+k3wYCvoW3eN+OcAfRPHbNFOIpeeFWJw+OJW4vIwb7cGrYNv8MO
            |          U6wjDmZI7bun5ZjkNcl58jMgtICZ4CLDoqamVcBF6Ahdb4SqlJN3m3RSqSBhu0b/XgMs8OWhG69l
            |          aCgL0kkw5XIIJkqRmozKsKz7A2cVEK8cmyJvwqcXETMyZfjAM5bxyLGSSjoNGK2NPx6CntB9TLkg
            |          UUOqQvhNEJ2K2a1/wczPoR0bT1k9YFUZGHPVrO9ZYTzDOecGj9/ib9G2buyjSICfyykOk8Hv5Uhu
            |          sf4Rl8+TOa3YglsuN16oFYFEVBAKtCGTKiMd40kkrufn2kftSDvGSdU3fTNjmqDlskVQlhhEzqHh
            |          cMcO9Eo7wJ1IBwRuS9gJidSKjFfnDzMePQeXsQre7ZEK/gtRGQQ+uWRxaprO32jch9b5f90F0YX9
            |          UjM5yw93GqjRhk64VZpBso4yJac7jAVgw3RMO8LlzckxTRP+Pdl8amsbs9Wy5PDbov9oO5TaNYeD
            |          MSbnyPRZT9+4uSuddSTbWz4Er/yHq1cq03o9ucuslUHRZCJ4aWYa1CMQURkvCvhTLlWouzJuQ6lm
            |          mTT1bQXEb0OSRpgEkwwHLjOab73xETv532uVXemsjPj8vpnrEZWVK4Oq/arEsZBMy147r8PYPiS/
            |          DEVLTUKd0KGo7i8SnxxH53w4HXTcMPrbXTYUEtTNH/t4SgoIrmw9lMpR2wLJkOxCGoW+mTYynPgK
            |          AbnDqbcI2F9KJWOmrHEudqLYmn/dkXx/DKTPhyX87f677T6boEtdA/3s3EVT+VsM78FdHiLqaF3z
            |          ufpIWdIeMaAU8B1AdaFA8/LiOVmIQGrvGac3S5TiHczHnHO5m4ND8ixGW1Cz
            |        </xenc:CipherValue>
            |      </xenc:CipherData>
            |    </xenc:EncryptedData>
            |  </s2:EncryptedAssertion>
            |</s:Response>
           """.trimMargin()

    private val incorrectEncryptedResponse =
            """
            |<s:Response $responseParams>
            |  <s2:Issuer>$incorrectIdpIssuer</s2:Issuer>
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
            |              U1eM1B55UmuK1vRfGItDbL2yJcuLTeEvKAAifZAKWghT6TOlcCVLlA+6IRPldhq1G6dvOb1c
            |              o2KQQL0V3yPT+D8s3+1cCEW3b8+jh+KoeaK4L5j8n//FLL4Z1dcvTnj60d5GLru/+RWCZhkz
            |              c37cutcgYuU3BxDhylfCP8EgdlIi2PgZWDbHegYOn6EH5YsX2fUpgB6X+pIOI1N+lh1xZph/
            |              4Qy9PuhK0tsInTLbVb4IQ1MuS2QDyRzwbojMBBTfp12tVTMJuxKK+yG0RkysDWBgs6PmEog4
            |              ZfGwVC1NwgYfsEaI7D+OfxeNGIatoASbgqruiGdHY3714xq1CDEqAg==
            |            </xenc:CipherValue>
            |          </xenc:CipherData>
            |        </xenc:EncryptedKey>
            |      </dsig:KeyInfo>
            |      <xenc:CipherData>
            |        <xenc:CipherValue>
            |          jjjIMaJF7L0M4gi4PARrt44bVht5wPWybC9E/WMsYQe3Rw3Mf7gp9qyE35cDOWYDzmitP8r+HPAw
            |          M7pgbjEB8//1nuEHl1yBv+zZ5G01rLQTPReErI8inEiSIFhk77JkJ1gwUK0x+zMySKklAkyGEoQP
            |          Zg/u7ah0EQYE6Ix/aKeqUR1rxwLEROuOD52pV3+4FGnJ3wR/1Urk5baXBSg56DFyo4ghiq7ssTkX
            |          7zHJSNlcyf7ENWs/x084UDBcLh3hWdyxJThKGOYFNmekUh1dSFq4Bhn+gDDNTUWEnlztiYhZ2XeI
            |          oFQkLR+KQb4I7oha5drH8FGZzrZ1P9pwBmobv8uab6aHTwuUkJzRW5p+1FSQLBIhLxQ23liVpmek
            |          ehtLPfb4PetwQtZ878NoIgh4uU+d3Fq468/DyjdUYmVAJfJxxnfpePFhacTMsS+uM84IXIQQ1Gvz
            |          3nUkKac7sDT6N6o5aufZsRcwjq7JmqQTcFqY/OOONz/6JJLuDouFrUWuHzq+gtd9T0IogxJl+ooR
            |          cByLFouFkrnX8SEYeBNWI3CRYNPf/Z6dL4nYnSdiCD3T2GdOjt5Y0WlVNCGrttE9C9NDnVkqHUlt
            |          ag9rA5SWdi/LxtD8nnwO5ZVhxj66BR1Y87+/6oH+GkLhyi8zj1IFlaHoRgfc9viHWvL8iBVlxuQ/
            |          Pun+x/Sc4J7FcTn/3ZsZYp9FQLXaSUtCRJeN27Brrh+BHSa4gHCkCXAQgO04ThTaTOhXAxPU7vIN
            |          aAbYaM2UYv/JAXdr3O/HDkNfNF2fA2xX10b/LUzR4CpxgbkKt1pbHeVMPZRKDrDlncEWtE70oZVi
            |          s0buxkkMbDNOxjlx+PIWyMG91mKgMlV53MQLjTHEpunoYyYbiLMVtECaitJP
            |        </xenc:CipherValue>
            |      </xenc:CipherData>
            |    </xenc:EncryptedData>
            |  </s2:EncryptedAssertion>
            |</s:Response>
           """.trimMargin()

    init {
        REQUEST_ID = "a6611f9cc-a8ba-46a6-b2ce-24dd8"
        System.setProperty(IMPLEMENTATION_PATH,
                Resources.getResource("implementation").path)
        System.setProperty(TEST_SP_METADATA_PROPERTY,
                Resources.getResource("test-sp-metadata.xml").path)

        "unsigned response with no issuer on response element should pass" {
            NodeDecorator(Common.buildDom(createResponse(issuer = ""))).let {
                SingleSignOnProfileVerifier(it).verify()
            }
        }

        "signed response with no issuer on response element should fail" {
            NodeDecorator(Common.buildDom(createResponse(issuer = "")), isSigned = true).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_a.message)
            }
        }

        "response with incorrect assertion issuer value should fail" {
            NodeDecorator(Common.buildDom(createResponse(assertionIssuer = "wrong"))).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_c.message)
            }
        }

        "response with no assertion should fail" {
            val noAssertionResponse = "<s:Response $responseParams/>"
            NodeDecorator(Common.buildDom(noAssertionResponse)).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_b.message)
            }
        }

        "unsigned response with encrypted assertion and correct issuer should pass" {
            NodeDecorator(Common.buildDom(correctEncryptedResponse)).let {
                CoreVerifierTest(it).verify()
                SingleSignOnProfileVerifier(it).verify()
            }
        }

        "unsigned response with encrypted assertion and incorrect issuer should fail" {
            NodeDecorator(Common.buildDom(incorrectEncryptedResponse)).let {
                shouldThrow<SAMLComplianceException> {
                    CoreVerifierTest(it).verify()
                    SingleSignOnProfileVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_a.message)
            }
        }
    }

    private fun createResponse(issuer: String = "<s2:Issuer>http://correct.idp.issuer</s2:Issuer>",
                               assertionIssuer: String = "http://correct.idp.issuer",
                               subjConf: String = createBearerSubjConf()): String {
        return """
            |<s:Response $responseParams>
            |  $issuer
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
                                     inResponseTo: String = "InResponseTo=\"$REQUEST_ID\""):
            String {
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

class CoreVerifierTest(samlNode: NodeDecorator) : CoreVerifier(samlNode)
