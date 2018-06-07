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

import io.kotlintest.forAll
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.shouldThrow
import io.kotlintest.specs.StringSpec
import org.codice.compliance.Common
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_3_1_a
import org.codice.compliance.SAMLProfiles_3_1_b
import org.codice.compliance.SAMLProfiles_3_1_c
import org.codice.compliance.utils.HOLDER_OF_KEY_URI
import org.codice.compliance.utils.PERSISTENT_ID
import org.codice.compliance.utils.SUCCESS
import org.codice.compliance.verification.profile.SingleSignOnProfileVerifier
import java.time.Instant
import java.util.UUID

@Suppress("StringLiteralDuplication")
class SingleSignOnProfileVerifierSpec : StringSpec() {
    private val correctType = "xsi:type=\"s2:KeyInfoConfirmationDataType\""
    private val correctKeyInfo = """
                |<ds:KeyInfo>
                |  <ds:KeyName>key</ds:KeyName>
                |</ds:KeyInfo>
                """.trimMargin()

    init {
        "response with correct holder-of-key subject confirmation should pass" {
            Common.buildDom(createResponse(createSubjConfData(keyInfo = correctKeyInfo))).let {
                SingleSignOnProfileVerifier(it).verifyHolderOfKey()
            }
        }

        "response with no subject confirmation data type should pass" {
            Common.buildDom(createResponse(createSubjConfData("", correctKeyInfo))).let {
                SingleSignOnProfileVerifier(it).verifyHolderOfKey()
            }
        }

        "response with incorrect subject confirmation data type should fail" {
            forAll(listOf("wrong", "s2:wrong", "s:KeyInfoConfirmationDataType")) {
                val type = "xsi:type=\"$it\""
                Common.buildDom(createResponse(createSubjConfData(type, correctKeyInfo))).let {
                    shouldThrow<SAMLComplianceException> {
                        SingleSignOnProfileVerifier(it).verifyHolderOfKey()
                    }.message?.shouldContain(SAMLProfiles_3_1_b.message)
                }
            }
        }

        "response with no subject confirmation data should fail" {
            Common.buildDom(createResponse("")).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verifyHolderOfKey()
                }.message?.shouldContain(SAMLProfiles_3_1_a.message)
            }
        }

        "response with no key info should fail" {
            Common.buildDom(createResponse(createSubjConfData(keyInfo = ""))).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verifyHolderOfKey()
                }.message?.shouldContain(SAMLProfiles_3_1_a.message)
            }
        }

        "response with multiple key values should fail" {
            val incorrectKeyInfo = """
                |<ds:KeyInfo>
                |  <ds:KeyValue>value</ds:KeyValue>
                |  <ds:KeyValue>value</ds:KeyValue>
                |</ds:KeyInfo>
                """.trimMargin()

            Common.buildDom(createResponse(createSubjConfData(keyInfo = incorrectKeyInfo))).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verifyHolderOfKey()
                }.message?.shouldContain(SAMLProfiles_3_1_c.message)
            }
        }

        "response with empty and not empty holder-of-key subject confirmation should fail" {
            val multipleSubjConf = """
                |  <s2:SubjectConfirmationData $correctType>
                |    <ds:KeyInfo>
                |      <ds:KeyName>key</ds:KeyName>
                |    </ds:KeyInfo>
                |  </s2:SubjectConfirmationData>
                |</s2:SubjectConfirmation>
                |<s2:SubjectConfirmation Method="$HOLDER_OF_KEY_URI">
                """.trimMargin()

            Common.buildDom(createResponse(multipleSubjConf)).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verifyHolderOfKey()
                }.message?.shouldContain(SAMLProfiles_3_1_a.message)
            }
        }

        "response with empty and not empty key info subject confirmation data should fail" {
            val multipleSubjConf = """
                |  <s2:SubjectConfirmationData $correctType>
                |    <ds:KeyInfo>
                |      <ds:KeyName>key</ds:KeyName>
                |    </ds:KeyInfo>
                |  </s2:SubjectConfirmationData>
                |</s2:SubjectConfirmation>
                |<s2:SubjectConfirmation Method="$HOLDER_OF_KEY_URI">
                |  <s2:SubjectConfirmationData $correctType/>
                """.trimMargin()

            Common.buildDom(createResponse(multipleSubjConf)).let {
                shouldThrow<SAMLComplianceException> {
                    SingleSignOnProfileVerifier(it).verifyHolderOfKey()
                }.message?.shouldContain(SAMLProfiles_3_1_a.message)
            }
        }
    }

    private fun createResponse(subjConfData: String): String {
        return """
            |<s:Response
            |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
            |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
            |xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            |xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
            |ID="${"a" + UUID.randomUUID().toString()}"
            |Version="2.0"
            |IssueInstant="${Instant.now()}">
            |  <s2:Assertion
            |  ID="${"a" + UUID.randomUUID().toString()}"
            |  Version="2.0"
            |  IssueInstant="${Instant.now()}">
            |    <s2:Issuer>https://localhost:8993/services/idp/login</s2:Issuer>
            |    <s2:Subject>
            |      <s2:NameID SPNameQualifier="http://sp.example.com/demo1/metadata.php"
            |      Format="$PERSISTENT_ID">
            |        admin
            |      </s2:NameID>
            |      <s2:SubjectConfirmation Method="$HOLDER_OF_KEY_URI">
            |        $subjConfData
            |      </s2:SubjectConfirmation>
            |    </s2:Subject>
            |  </s2:Assertion>
            |  <s:Status>
            |    <s:StatusCode Value="$SUCCESS"></s:StatusCode>
            |  </s:Status>
            |</s:Response>
           """.trimMargin()
    }

    private fun createSubjConfData(type: String = correctType, keyInfo: String): String {
        return """
                |<s2:SubjectConfirmationData $type>
                |  $keyInfo
                |</s2:SubjectConfirmationData>
                """.trimMargin()
    }
}
