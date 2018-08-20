/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compilance.verification.profile.subject.confirmations

import com.google.common.io.Resources
import io.kotlintest.forAll
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.shouldThrow
import io.kotlintest.specs.StringSpec
import org.codice.compliance.Common
import org.codice.compliance.IMPLEMENTATION_PATH
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_4_1_4_2_e
import org.codice.compliance.SAMLProfiles_4_1_4_2_f
import org.codice.compliance.SAMLProfiles_4_1_4_2_g
import org.codice.compliance.SAMLProfiles_4_1_4_2_h
import org.codice.compliance.SAMLProfiles_4_1_4_2_i
import org.codice.compliance.TEST_SP_METADATA_PROPERTY
import org.codice.compliance.utils.BEARER
import org.codice.compliance.utils.HOLDER_OF_KEY_URI
import org.codice.compliance.utils.TestCommon.Companion.REQUEST_ID
import org.codice.compliance.verification.profile.subject.confirmations.BearerSubjectConfirmationVerifier
import java.time.Instant
import java.util.UUID

@Suppress("StringLiteralDuplication")
class BearerSubjectConfirmationVerifierSpec : StringSpec() {
    private val correctIdpIssuer = "http://correct.idp.issuer"

    private val responseParams = """
        |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
        |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
        |xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
        |ID="${"a" + UUID.randomUUID().toString()}"
        |Version="2.0"
        |IssueInstant="${Instant.now()}"
        """.trimMargin()

    private val basicBearerSubjConf = """
            |<s2:SubjectConfirmation Method="$BEARER">
            |  <s2:SubjectConfirmationData/>
            |</s2:SubjectConfirmation>
            """.trimMargin()

    init {
        REQUEST_ID = "a" + UUID.randomUUID().toString()
        System.setProperty(IMPLEMENTATION_PATH,
                Resources.getResource("implementation").path)
        System.setProperty(TEST_SP_METADATA_PROPERTY,
                Resources.getResource("test-sp-metadata.xml").path)

        "response containing an assertion with no bearer subject confirmation should fail" {
            val nonBearerSubjConf = """
            |<s2:SubjectConfirmation Method="$HOLDER_OF_KEY_URI">
            |  <s2:SubjectConfirmationData/>
            |</s2:SubjectConfirmation>
            """.trimMargin()

            Common.buildDom(createResponse(
                    assertion = createAssertion(subjConf = nonBearerSubjConf))).let {
                shouldThrow<SAMLComplianceException> {
                    BearerSubjectConfirmationVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_e.message)
            }
        }

        "response with one or multiple bearer subject confirmation should pass" {
            val oneBearerSubjConf = """
            |${createBearerSubjConf()}
            |<s2:SubjectConfirmation Method="$HOLDER_OF_KEY_URI">
            |  <s2:SubjectConfirmationData/>
            |</s2:SubjectConfirmation>
            """.trimMargin()

            val multipleBearerSubjConf = """
            |${createBearerSubjConf()}
            |${createBearerSubjConf()}
            """.trimMargin()

            forAll(listOf(oneBearerSubjConf, multipleBearerSubjConf)) {
                Common.buildDom(createResponse(
                        assertion = createAssertion(subjConf = it))).let {
                    BearerSubjectConfirmationVerifier(it).verify()
                }
            }
        }

        "bearer subject confirmation with correct attributes and authn statement should pass" {
            Common.buildDom(createResponse(
                    assertion = createAssertion(subjConf = createBearerSubjConf()))).let {
                BearerSubjectConfirmationVerifier(it).verify()
            }
        }

        "response with no bearer subject confirmation with correct recipient should fail" {
            val bearerSubjConfsWithIncorrectRecipient = """
                |$basicBearerSubjConf
                |${createBearerSubjConf(recipient = "Recipient=\"incorrect/uri\"")}
                """.trimMargin()
            val bearerSubjConfsWithNoRecipient = """
                |$basicBearerSubjConf
                |${createBearerSubjConf(recipient = "")}
                """.trimMargin()

            forAll(listOf(bearerSubjConfsWithIncorrectRecipient, bearerSubjConfsWithNoRecipient)) {
                Common.buildDom(createResponse(
                        assertion = createAssertion(subjConf = it))).let {
                    shouldThrow<SAMLComplianceException> {
                        BearerSubjectConfirmationVerifier(it).verify()
                    }.message?.shouldContain(SAMLProfiles_4_1_4_2_f.message)
                }
            }
        }

        "response with no bearer subject confirmation with NotOnOrAfter should fail" {
            val bearerSubjConfs = """
                |$basicBearerSubjConf
                |${createBearerSubjConf(notOnOrAfter = "")}
                """.trimMargin()

            Common.buildDom(createResponse(
                    assertion = createAssertion(subjConf = bearerSubjConfs))).let {
                shouldThrow<SAMLComplianceException> {
                    BearerSubjectConfirmationVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_f.message)
            }
        }

        "response with no bearer subject confirmation with InResponseTo should fail" {
            val bearerSubjConfs = """
                |$basicBearerSubjConf
                |${createBearerSubjConf(inResponseTo = "")}
                """.trimMargin()

            Common.buildDom(createResponse(
                    assertion = createAssertion(subjConf = bearerSubjConfs))).let {
                shouldThrow<SAMLComplianceException> {
                    BearerSubjectConfirmationVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_f.message)
            }
        }

        "response with a bearer subject confirmation with a NotBefore should fail" {
            val bearerSubjConfs = """
                |$basicBearerSubjConf
                |${createBearerSubjConf(extraAttribute = "NotBefore=\"${Instant.now()}\"")}
                """.trimMargin()

            Common.buildDom(createResponse(
                    assertion = createAssertion(subjConf = bearerSubjConfs))).let {
                shouldThrow<SAMLComplianceException> {
                    BearerSubjectConfirmationVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_f.message)
            }
        }

        "response with no bearer assertion containing an AuthnStatement should fail" {
            Common.buildDom(createResponse(
                    assertion = createAssertion(authnStatement = ""))).let {
                shouldThrow<SAMLComplianceException> {
                    BearerSubjectConfirmationVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_g.message)
            }
        }

        "response with no SessionIndex when idp supports slo should fail" {
            Common.buildDom(createResponse(
                    assertion = createAssertion(authnStatement = "<s2:AuthnStatement/>"))).let {
                shouldThrow<SAMLComplianceException> {
                    BearerSubjectConfirmationVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_h.message)
            }
        }

        "response with a bearer assertion with correct Audience should pass" {
            Common.buildDom(createResponse(assertion =
            createAssertion(audience = "https://samlhost:8993/services/saml"))).let {
                BearerSubjectConfirmationVerifier(it).verify()
            }
        }

        "response with a bearer assertion with incorrect Audience should fail" {
            val correctAndIncorrectAssertions = """
                |${createAssertion()}
                |${createAssertion(audience = "wrong")}
                """.trimMargin()

            val incorrectAssertions = listOf(createAssertion(audience = ""),
                    createAssertion(audience = "wrong"),
                    correctAndIncorrectAssertions)

            forAll(incorrectAssertions) {
                Common.buildDom(createResponse(assertion = it)).let {
                    shouldThrow<SAMLComplianceException> {
                        BearerSubjectConfirmationVerifier(it).verify()
                    }.message?.shouldContain(SAMLProfiles_4_1_4_2_i.message)
                }
            }
        }

        "response with multiple <AudienceRestriction>s should fail" {
            val assertion = """
            |<s2:Assertion>
            |  <s2:Issuer>$correctIdpIssuer</s2:Issuer>
            |  <s2:Subject>
            |    ${createBearerSubjConf()}
            |  </s2:Subject>
            |  <s2:AuthnStatement SessionIndex="0"/>
            |  <s2:Conditions>
            |    <s2:AudienceRestriction>
            |      <s2:Audience>https://samlhost:8993/services/saml</s2:Audience>
            |    </s2:AudienceRestriction>
            |    <s2:AudienceRestriction>
            |      <s2:Audience>https://samlhost:8993/services/saml</s2:Audience>
            |    </s2:AudienceRestriction>
            |  </s2:Conditions>
            |</s2:Assertion>
           """.trimMargin()

            Common.buildDom(createResponse(assertion = assertion)).let {
                shouldThrow<SAMLComplianceException> {
                    BearerSubjectConfirmationVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_1_4_2_i.message)
            }
        }
    }

    private fun createResponse(
        isSigned: Boolean = false,
        issuer: String = "<s2:Issuer>$correctIdpIssuer</s2:Issuer>",
        assertion: String = createAssertion()
    ): String {

        val signature = if (isSigned) "<ds:Signature/>" else ""
        return """
            |<s:Response $responseParams>
            |  $issuer
            |  $signature
            |  $assertion
            |</s:Response>
           """.trimMargin()
    }

    private fun createAssertion(
        assertionIssuer: String = correctIdpIssuer,
        subjConf: String = createBearerSubjConf(),
        authnStatement: String = "<s2:AuthnStatement SessionIndex=\"0\"/>",
        audience: String = "https://samlhost:8993/services/saml"
    ): String {

        return """
            |<s2:Assertion>
            |  <s2:Issuer>$assertionIssuer</s2:Issuer>
            |  <s2:Subject>
            |    $subjConf
            |  </s2:Subject>
            |  $authnStatement
            |  <s2:Conditions>
            |    <s2:AudienceRestriction>
            |      <s2:Audience>$audience</s2:Audience>
            |    </s2:AudienceRestriction>
            |  </s2:Conditions>
            |</s2:Assertion>
           """.trimMargin()
    }

    private fun createBearerSubjConf(
        recipient: String = "Recipient=\"http://correct.uri\"",
        notOnOrAfter: String = "NotOnOrAfter=\"${Instant.now()}\"",
        inResponseTo: String = "InResponseTo=\"$REQUEST_ID\"",
        extraAttribute: String = ""
    ): String {
        return """
            |<s2:SubjectConfirmation Method="$BEARER">
            |  <s2:SubjectConfirmationData
            |  $extraAttribute
            |  $recipient
            |  $notOnOrAfter
            |  $inResponseTo/>
            |</s2:SubjectConfirmation>
            """.trimMargin()
    }
}
