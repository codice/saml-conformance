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

import io.kotlintest.forAll
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.shouldThrow
import io.kotlintest.specs.StringSpec
import io.mockk.every
import io.mockk.mockk
import org.codice.compliance.Common.Companion.buildDom
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCoreRefMessage
import org.codice.compliance.SAMLCore_4_1_3_2_a
import org.codice.compliance.SAMLCore_4_1_3_2_b
import org.codice.compliance.utils.TestCommon.Companion.ASSERTION_NAMESPACE
import org.codice.compliance.utils.TestCommon.Companion.PROTOCOL_NAMESPACE
import org.codice.compliance.verification.core.SamlVersioningVerifier
import java.time.Instant

class SamlVersioningVerifierSpec : StringSpec() {
    init {
        val specRefMsg = mockk<SAMLCoreRefMessage>()
        every { specRefMsg.message } returns "Test message"
        every { specRefMsg.name } returns "Test"

        val instant = Instant.now()
        val response = { resVersion: String, resUri: String?, version: String, uri: String? ->
            """
            |<s:Response xmlns:s="$resUri" ID="id" Version="$resVersion" IssueInstant="$instant">
            |  <s:Status>
            |    <s:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            |  </s:Status>
            |  <s2:Assertion xmlns:s2="$uri" ID="id" IssueInstant="$instant" Version="$version">
            |    <s2:Issuer>https://localhost:8993/services/idp/login</s2:Issuer>
            |  </s2:Assertion>
            |</s:Response>
           """.trimMargin()
        }

        "response with incorrect versions fails" {
            forAll(listOf("1.0", "1.1", "3.0", "2")) { version ->
                buildDom(
                    response(version, PROTOCOL_NAMESPACE, "2.0", ASSERTION_NAMESPACE)).let {
                    shouldThrow<SAMLComplianceException> {
                        SamlVersioningVerifier(it).verify()
                    }
                }
            }
        }

        "response with correct version should pass" {
            buildDom(
                response("2.0", PROTOCOL_NAMESPACE, "2.0", ASSERTION_NAMESPACE)).let {
                SamlVersioningVerifier(it).verify()
            }
        }

        "response with version 1.0 should fail with SAMLCore_4_1_3_2_a" {
            buildDom(
                response("1.0", PROTOCOL_NAMESPACE, "1.0", ASSERTION_NAMESPACE)).let {
                shouldThrow<SAMLComplianceException> {
                    SamlVersioningVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_4_1_3_2_a.message)
            }
        }

        "response with version 3.0 should fail with SAMLCore_4_1_3_2_b" {
            buildDom(
                response("3.0", PROTOCOL_NAMESPACE, "3.0", ASSERTION_NAMESPACE)).let {
                shouldThrow<SAMLComplianceException> {
                    SamlVersioningVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_4_1_3_2_b.message)
            }
        }

        "response with incorrect assertion versions fails" {
            forAll(listOf("1.0", "1.1", "3.0", "2")) { version ->
                buildDom(
                    response("2.0", PROTOCOL_NAMESPACE, version, ASSERTION_NAMESPACE)).let {
                    shouldThrow<SAMLComplianceException> {
                        SamlVersioningVerifier(it).verify()
                    }
                }
            }
        }

        val incorrectNamespaces = listOf("incorrect_SAML_namespace",
            "urn:oasis:names:tc:SAML:1.0:protocol", "urn:oasis:names:tc:SAML:3.0:protocol")

        "response with correct namespace URIs passes" {
            buildDom(
                response("2.0", PROTOCOL_NAMESPACE, "2.0", ASSERTION_NAMESPACE)).let {
                SamlVersioningVerifier(it).verify()
            }
        }

        "response with incorrect namespace URIs fails" {
            forAll(incorrectNamespaces) { uri ->
                buildDom(
                    response("2.0", uri, "2.0", ASSERTION_NAMESPACE)).let {
                    shouldThrow<SAMLComplianceException> {
                        SamlVersioningVerifier(it).verify()
                    }
                }
            }
        }

        "response with incorrect namespace URIs on the response element fails" {
            forAll(incorrectNamespaces) { uri ->
                buildDom(
                    response("2.0", PROTOCOL_NAMESPACE, "2.0", uri)).let {
                    shouldThrow<SAMLComplianceException> {
                        SamlVersioningVerifier(it).verify()
                    }
                }
            }
        }
    }
}
