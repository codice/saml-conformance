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
import org.codice.compliance.SAMLCore_3_2_2_2_a
import org.codice.compliance.SAMLCore_3_2_2_a
import org.codice.compliance.SAMLCore_3_2_2_b
import org.codice.compliance.SAMLCore_3_2_2_d
import org.codice.compliance.SAMLCore_3_2_2_e
import org.codice.compliance.SAMLGeneral_e
import org.codice.compliance.TEST_SP_METADATA_PROPERTY
import org.codice.compliance.utils.CONSENT
import org.codice.compliance.utils.DESTINATION
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.utils.PARTIAL_LOGOUT
import org.codice.compliance.utils.REQUESTER
import org.codice.compliance.utils.SUCCESS
import org.codice.compliance.utils.TestCommon.Companion.REQUEST_ID
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.compliance.verification.core.ResponseVerifier
import org.codice.security.saml.SamlProtocol
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.saml.SamlProtocol.POST_BINDING
import org.joda.time.DateTime
import org.opensaml.saml.common.SAMLVersion.VERSION_20
import org.opensaml.saml.saml2.core.RequestAbstractType
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import java.time.Instant
import java.util.UUID

class ResponseVerifierSpec : StringSpec() {

    private val request by lazy {
        AuthnRequestBuilder().buildObject().apply {
            issuer = IssuerBuilder().buildObject().apply { value = currentSPIssuer }
            assertionConsumerServiceURL = "https://localhost:8993/services/idp/login"
            id = REQUEST_ID
            version = VERSION_20
            issueInstant = DateTime()
            destination = "https://localhost:8993/services/idp/login"
            protocolBinding = POST_BINDING
            isForceAuthn = false
            setIsPassive(false)
        }
    }

    private val incorrectUri = "incorrect/uri"
    private val correctUri = "http://correct.uri"

    init {
        REQUEST_ID = "a" + UUID.randomUUID().toString()
        System.setProperty(TEST_SP_METADATA_PROPERTY,
                Resources.getResource("test-sp-metadata.xml").path)

        "response with correct fields should pass" {
            NodeDecorator(Common.buildDom(createResponse())).let {
                ResponseVerifierTest(request, it, HTTP_POST).verify()
            }
        }

        "response with non-unique ID should fail" {
            NodeDecorator(Common.buildDom(createResponse(id = "not-unique-id"))).let {
                ResponseVerifierTest(request, it, HTTP_POST).verify()
            }

            NodeDecorator(Common.buildDom(createResponse(id = "not-unique-id"))).let {
                shouldThrow<SAMLComplianceException> {
                    ResponseVerifierTest(request, it, HTTP_POST).verify()
                }.message?.apply {
                    shouldContain(SAMLCore_1_3_4_a.message)
                    shouldContain(SAMLCore_3_2_2_a.message)
                }
            }
        }

        "response with incorrect InResponseTo should fail" {
            NodeDecorator(Common.buildDom(createResponse(inResponseTo = "incorrect"))).let {
                shouldThrow<SAMLComplianceException> {
                    ResponseVerifierTest(request, it, HTTP_POST).verify()
                }.message?.shouldContain(SAMLCore_3_2_2_b.message)
            }
        }

        "response with blank version should fail" {
            NodeDecorator(Common.buildDom(createResponse(version = " "))).let {
                shouldThrow<SAMLComplianceException> {
                    ResponseVerifierTest(request, it, HTTP_POST).verify()
                }.message?.shouldContain(SAMLCore_1_3_1_a.message)
            }
        }

        "response with non-utc instant issuer should fail" {
            NodeDecorator(Common.buildDom(
                    createResponse(instant = "2018-05-01T06:15:30-07:00"))).let {
                shouldThrow<SAMLComplianceException> {
                    ResponseVerifierTest(request, it, HTTP_POST).verify()
                }.message?.apply {
                    shouldContain(SAMLCore_1_3_3_a.message)
                    shouldContain(SAMLCore_3_2_2_d.message)
                }
            }
        }

        "response with correct destination should pass" {
            NodeDecorator(Common.buildDom(
                    createResponse(attribute = "$DESTINATION=\"$correctUri\""))).let {
                ResponseVerifierTest(request, it, HTTP_POST).verify()
            }
        }

        "response with incorrect destination should fail" {
            NodeDecorator(Common.buildDom(
                    createResponse(attribute = "$DESTINATION=\"$incorrectUri\""))).let {
                shouldThrow<SAMLComplianceException> {
                    ResponseVerifierTest(request, it, HTTP_POST).verify()
                }.message?.shouldContain(SAMLCore_3_2_2_e.message)
            }
        }

        "response with correct consent should pass" {
            NodeDecorator(Common.buildDom(
                    createResponse(attribute = "$CONSENT=\"$correctUri\""))).let {
                ResponseVerifierTest(request, it, HTTP_POST).verify()
            }
        }

        "response with non-uri consent should fail" {
            NodeDecorator(Common.buildDom(
                    createResponse(attribute = "$CONSENT=\"$incorrectUri\""))).let {
                shouldThrow<SAMLComplianceException> {
                    ResponseVerifierTest(request, it, HTTP_POST).verify()
                }.message?.shouldContain(SAMLCore_1_3_2_a.message)
            }
        }

        "response with a top level status code that isn't success should fail" {
            NodeDecorator(Common.buildDom(createResponse(statusCode = REQUESTER))).let {
                shouldThrow<SAMLComplianceException> {
                    ResponseVerifierTest(request, it, HTTP_POST).verify()
                }.message?.shouldContain(SAMLGeneral_e.message)
            }
        }

        "response with a second-level status code as top-level should fail" {
            NodeDecorator(Common.buildDom(createResponse(statusCode = PARTIAL_LOGOUT))).let {
                shouldThrow<SAMLComplianceException> {
                    ResponseVerifierTest(request, it, HTTP_POST).verify()
                }.message?.shouldContain(SAMLCore_3_2_2_2_a.message)
            }
        }

        "response with a blank status message should fail" {
            NodeDecorator(Common.buildDom(createResponse(statusMessage = " "))).let {
                shouldThrow<SAMLComplianceException> {
                    ResponseVerifierTest(request, it, HTTP_POST).verify()
                }.message?.shouldContain(SAMLCore_1_3_1_a.message)
            }
        }
    }

    @Suppress("LongParameterList")
    private fun createResponse(id: String = UUID.randomUUID().toString().replace("-", ""),
                               version: String = "2.0",
                               inResponseTo: String = REQUEST_ID,
                               attribute: String = "",
                               instant: String = Instant.now().toString(),
                               statusCode: String = SUCCESS,
                               statusMessage: String = "Status Message"): String {
        return """
            |<s:Response
            |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
            |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
            |ID="$id"
            |Version="$version"
            |$attribute
            |IssueInstant="$instant"
            |InResponseTo="$inResponseTo">
            |  <s2:Issuer>https://localhost:8993/services/idp/login</s2:Issuer>
            |  <s:Status>
            |    <s:StatusCode Value="$statusCode"/>
            |    <s:StatusMessage>$statusMessage</s:StatusMessage>
            |  </s:Status>
            |</s:Response>
           """.trimMargin()
    }

    private class ResponseVerifierTest(samlRequest: RequestAbstractType,
                                       samlResponseDom: NodeDecorator,
                                       binding: SamlProtocol.Binding)
        : ResponseVerifier(samlRequest, samlResponseDom, binding)
}
