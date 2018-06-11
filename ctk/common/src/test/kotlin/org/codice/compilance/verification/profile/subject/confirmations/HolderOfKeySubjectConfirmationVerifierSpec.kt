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
package org.codice.compilance.verification.profile.subject.confirmations

import io.kotlintest.forAll
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.shouldThrow
import io.kotlintest.specs.StringSpec
import org.codice.compliance.Common
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_3_1_a
import org.codice.compliance.SAMLProfiles_3_1_b
import org.codice.compliance.SAMLProfiles_3_1_c
import org.codice.compliance.utils.BEARER
import org.codice.compliance.utils.HOLDER_OF_KEY_URI
import org.codice.compliance.verification.profile.subject.confirmations.HolderOfKeySubjectConfirmationVerifier
import java.time.Instant
import java.util.UUID

@Suppress("StringLiteralDuplication")
class HolderOfKeySubjectConfirmationVerifierSpec : StringSpec() {
    private val correctType = "xsi:type=\"s2:KeyInfoConfirmationDataType\""
    private val correctKeyInfo = """
                |<ds:KeyInfo>
                |  <ds:KeyName>key</ds:KeyName>
                |</ds:KeyInfo>
                """.trimMargin()

    init {
        "response with correct holder-of-key subject confirmation should pass" {
            Common.buildDom(createResponse(
                    subjConf = createHolderOfKeySubjConf(keyInfo = correctKeyInfo))).let {
                HolderOfKeySubjectConfirmationVerifier(it).verify()
            }
        }

        "response with no holder-of-key subject confirmation should pass" {
            val basicBearerSubjConf = """
            |<s2:SubjectConfirmation Method="$BEARER">
            |  <s2:SubjectConfirmationData/>
            |</s2:SubjectConfirmation>
            """.trimMargin()

            Common.buildDom(createResponse(subjConf = basicBearerSubjConf)).let {
                HolderOfKeySubjectConfirmationVerifier(it).verify()
            }
        }

        "holder-of-key with no subject confirmation data type should pass" {
            Common.buildDom(createResponse(
                    subjConf = createHolderOfKeySubjConf("", correctKeyInfo))).let {
                HolderOfKeySubjectConfirmationVerifier(it).verify()
            }
        }

        "holder-of-key with incorrect subject confirmation data type should fail" {
            forAll(listOf("wrong", "s2:wrong", "s:KeyInfoConfirmationDataType")) {
                val type = "xsi:type=\"$it\""
                Common.buildDom(createResponse(
                        subjConf = createHolderOfKeySubjConf(type, correctKeyInfo))).let {
                    shouldThrow<SAMLComplianceException> {
                        HolderOfKeySubjectConfirmationVerifier(it).verify()
                    }.message?.shouldContain(SAMLProfiles_3_1_b.message)
                }
            }
        }

        "holder-of-key with no subject confirmation data should fail" {
            val holderOfKeyWithNoSubjConfData =
                    "<s2:SubjectConfirmation Method=\"$HOLDER_OF_KEY_URI\"/>"
            Common.buildDom(createResponse(subjConf = holderOfKeyWithNoSubjConfData)).let {
                shouldThrow<SAMLComplianceException> {
                    HolderOfKeySubjectConfirmationVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_3_1_a.message)
            }
        }

        "holder-of-key with no key info should fail" {
            Common.buildDom(createResponse(
                    subjConf = createHolderOfKeySubjConf(keyInfo = ""))).let {
                shouldThrow<SAMLComplianceException> {
                    HolderOfKeySubjectConfirmationVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_3_1_a.message)
            }
        }

        "holder-of-key with multiple key values should fail" {
            val multipleKeyInfos = """
                |<ds:KeyInfo>
                |  <ds:KeyValue>value</ds:KeyValue>
                |  <ds:KeyValue>value</ds:KeyValue>
                |</ds:KeyInfo>
                """.trimMargin()

            Common.buildDom(createResponse(
                    subjConf = createHolderOfKeySubjConf(keyInfo = multipleKeyInfos))).let {
                shouldThrow<SAMLComplianceException> {
                    HolderOfKeySubjectConfirmationVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_3_1_c.message)
            }
        }

        "holder-of-key with one empty and one not empty subject confirmation should fail" {
            val multipleSubjConf = """
                |${createHolderOfKeySubjConf()}
                |<s2:SubjectConfirmation Method="$HOLDER_OF_KEY_URI"/>
                """.trimMargin()

            Common.buildDom(createResponse(subjConf = multipleSubjConf)).let {
                shouldThrow<SAMLComplianceException> {
                    HolderOfKeySubjectConfirmationVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_3_1_a.message)
            }
        }

        "holder-of-key with one empty and one not empty subject confirmation data should fail" {
            val multipleSubjConf = """
                |${createHolderOfKeySubjConf()}
                |<s2:SubjectConfirmation Method="$HOLDER_OF_KEY_URI">
                |  <s2:SubjectConfirmationData $correctType/>
                |</s2:SubjectConfirmation>
                """.trimMargin()

            Common.buildDom(createResponse(subjConf = multipleSubjConf)).let {
                shouldThrow<SAMLComplianceException> {
                    HolderOfKeySubjectConfirmationVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_3_1_a.message)
            }
        }
    }

    private fun createResponse(subjConf: String): String {
        return """
            |<s:Response
            |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
            |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
            |xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            |xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            |ID="${"a" + UUID.randomUUID().toString()}"
            |Version="2.0"
            |IssueInstant="${Instant.now()}">
            |  <s2:Assertion>
            |    <s2:Subject>
            |      $subjConf
            |    </s2:Subject>
            |  </s2:Assertion>
            |</s:Response>
           """.trimMargin()
    }

    private fun createHolderOfKeySubjConf(type: String = correctType,
                                          keyInfo: String = correctKeyInfo): String {
        return """
            |<s2:SubjectConfirmation Method="$HOLDER_OF_KEY_URI">
            |  <s2:SubjectConfirmationData $type>
            |    $keyInfo
            |  </s2:SubjectConfirmationData>
            |</s2:SubjectConfirmation>
            """.trimMargin()
    }
}
