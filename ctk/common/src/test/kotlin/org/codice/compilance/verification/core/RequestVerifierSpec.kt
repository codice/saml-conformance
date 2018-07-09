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

import com.google.common.io.Resources
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
import org.codice.compliance.SAMLCore_3_2_1_e
import org.codice.compliance.TEST_SP_METADATA_PROPERTY
import org.codice.compliance.utils.CONSENT
import org.codice.compliance.utils.DESTINATION
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.verification.core.RequestVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import java.time.Instant
import java.util.UUID

class RequestVerifierSpec : StringSpec() {
    init {
        val incorrectUri = "incorrect/uri"
        val correctUri = "http://correct.uri"
        System.setProperty(TEST_SP_METADATA_PROPERTY,
                Resources.getResource("test-sp-metadata.xml").path)

        "request with correct ID, version and instant should pass" {
            NodeDecorator(Common.buildDom(createRequest())).let {
                RequestVerifierTest(it).verify()
            }
        }

        "request with non-unique ID should fail" {
            NodeDecorator(Common.buildDom(createRequest(id = "id"))).let {
                RequestVerifierTest(it).verify()
            }

            NodeDecorator(Common.buildDom(createRequest(id = "id"))).let {
                shouldThrow<SAMLComplianceException> {
                    RequestVerifierTest(it).verify()
                }.message?.apply {
                    shouldContain(SAMLCore_1_3_4_a.message)
                    shouldContain(SAMLCore_3_2_1_a.message)
                }
            }
        }

        "request with incorrect version (empty) should fail" {
            NodeDecorator(Common.buildDom(createRequest(version = ""))).let {
                shouldThrow<SAMLComplianceException> {
                    RequestVerifierTest(it).verify()
                }.message?.apply {
                    shouldContain(SAMLCore_1_3_1_a.message)
                    shouldContain(SAMLCore_3_2_1_b.message)
                }
            }
        }

        "request with incorrect instant (non-UTC) should fail" {
            NodeDecorator(Common.buildDom(
                    createRequest(instant = "2018-05-01T06:15:30-07:00"))).let {
                shouldThrow<SAMLComplianceException> {
                    RequestVerifierTest(it).verify()
                }.message?.apply {
                    shouldContain(SAMLCore_1_3_3_a.message)
                    shouldContain(SAMLCore_3_2_1_c.message)
                }
            }
        }

        "request with correct destination should pass" {
            NodeDecorator(Common.buildDom(
                    createRequest(attribute = "$DESTINATION=\"$correctUri\""))).let {
                RequestVerifierTest(it).verify()
            }
        }

        "request with incorrect destination should fail" {
            NodeDecorator(Common.buildDom(
                    createRequest(attribute = "$DESTINATION=\"$incorrectUri\""))).let {
                shouldThrow<SAMLComplianceException> {
                    RequestVerifierTest(it).verify()
                }.message?.shouldContain(SAMLCore_3_2_1_e.message)
            }
        }

        "request with correct consent should pass" {
            NodeDecorator(Common.buildDom(
                    createRequest(attribute = "$CONSENT=\"$correctUri\""))).let {
                RequestVerifierTest(it).verify()
            }
        }

        "request with incorrect consent (relative URI) should fail" {
            NodeDecorator(Common.buildDom(
                    createRequest(attribute = "$CONSENT=\"$incorrectUri\""))).let {
                shouldThrow<SAMLComplianceException> {
                    RequestVerifierTest(it).verify()
                }.message?.shouldContain(SAMLCore_1_3_2_a.message)
            }
        }
    }

    private fun createRequest(id: String? = UUID.randomUUID().toString().replace("-", ""),
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

    private class RequestVerifierTest(samlRequestDom: NodeDecorator) :
            RequestVerifier(samlRequestDom, HTTP_POST)
}
