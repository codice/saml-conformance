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
package org.codice.compilance.verification.core

import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.shouldThrow
import io.kotlintest.specs.StringSpec
import org.codice.compliance.Common
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_1_3_1_a
import org.codice.compliance.SAMLCore_1_3_2_a
import org.codice.compliance.SAMLCore_1_3_3_a
import org.codice.compliance.SAMLCore_1_3_4_a
import org.codice.compliance.SAMLCore_3_2_1_a
import org.codice.compliance.SAMLCore_3_2_1_b
import org.codice.compliance.SAMLCore_3_2_1_c
import org.codice.compliance.verification.core.RequestVerifier
import org.w3c.dom.Node
import java.time.Instant
import java.util.UUID

class RequestVerifierSpec : StringSpec() {
    init {
        val incorrectUri = "incorrect/uri"
        val correctUri = "http://correct.uri"

        "response with correct ID, version and instant should pass" {
            Common.buildDom(createResponse()).let {
                RequestVerifierTest(it).verify()
            }
        }

        "response with incorrect ID should fail" {
            Common.buildDom(createResponse(id = "id")).let {
                RequestVerifierTest(it).verify()
            }

            val message = Common.buildDom(createResponse(id = "id")).let {
                shouldThrow<SAMLComplianceException> {
                    RequestVerifierTest(it).verify()
                }.message
            }
            message?.shouldContain(SAMLCore_1_3_4_a.message)
            message?.shouldContain(SAMLCore_3_2_1_a.message)
        }

        "response with incorrect version should fail" {
            val message = Common.buildDom(createResponse(version = "")).let {
                shouldThrow<SAMLComplianceException> {
                    RequestVerifierTest(it).verify()
                }.message
            }
            message?.shouldContain(SAMLCore_1_3_1_a.message)
            message?.shouldContain(SAMLCore_3_2_1_b.message)
        }

        "response with incorrect instant should fail" {
            val message = Common.buildDom(
                createResponse(instant = "2018-05-01T06:15:30-07:00")).let {
                shouldThrow<SAMLComplianceException> {
                    RequestVerifierTest(it).verify()
                }.message
            }
            message?.shouldContain(SAMLCore_1_3_3_a.message)
            message?.shouldContain(SAMLCore_3_2_1_c.message)
        }

        "response with correct destination should pass" {
            Common.buildDom(createResponse(attribute = "Destination=\"$correctUri\"")).let {
                RequestVerifierTest(it).verify()
            }
        }

        "response with incorrect destination should fail" {
            Common.buildDom(createResponse(attribute = "Destination=\"$incorrectUri\"")).let {
                shouldThrow<SAMLComplianceException> {
                    RequestVerifierTest(it).verify()
                }.message?.shouldContain(SAMLCore_1_3_2_a.message)
            }
        }

        "response with correct consent should pass" {
            Common.buildDom(createResponse(attribute = "Consent=\"$correctUri\"")).let {
                RequestVerifierTest(it).verify()
            }
        }

        "response with incorrect consent should fail" {
            Common.buildDom(createResponse(attribute = "Consent=\"$incorrectUri\"")).let {
                shouldThrow<SAMLComplianceException> {
                    RequestVerifierTest(it).verify()
                }.message?.shouldContain(SAMLCore_1_3_2_a.message)
            }
        }
    }

    private fun createResponse(id: String? = UUID.randomUUID().toString().replace("-", ""),
        version: String? = "2.0",
        attribute: String = "",
        instant: String = Instant.now().toString()): String {
        return """
            |<s:LogoutRequest
            |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
            |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
            |ID="$id"
            |Version="$version"
            |$attribute
            |IssueInstant="$instant">
            |  <s2:Issuer>https://localhost:8993/services/idp/login</s2:Issuer>
            |  <s2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
            |    admin
            |  </s2:NameID>
            |</s:LogoutRequest>
           """.trimMargin()
    }

    private class RequestVerifierTest(samlRequestDom: Node) : RequestVerifier(samlRequestDom)
}
