/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compilance.verification.core

import com.google.common.io.Resources
import io.kotlintest.extensions.TestListener
import io.kotlintest.matchers.boolean.shouldBeFalse
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.specs.StringSpec
import org.codice.compilance.ReportListener
import org.codice.compliance.Common
import org.codice.compliance.SAMLCore_1_3_1_a
import org.codice.compliance.SAMLCore_1_3_2_a
import org.codice.compliance.SAMLCore_1_3_3_a
import org.codice.compliance.SAMLCore_1_3_4_a
import org.codice.compliance.SAMLCore_3_2_1_a
import org.codice.compliance.SAMLCore_3_2_1_b
import org.codice.compliance.SAMLCore_3_2_1_c
import org.codice.compliance.SAMLCore_3_2_1_e
import org.codice.compliance.TEST_SP_METADATA_PROPERTY
import org.codice.compliance.report.Report
import org.codice.compliance.Section.CORE_1_3
import org.codice.compliance.Section.CORE_3_2
import org.codice.compliance.utils.CONSENT
import org.codice.compliance.utils.DESTINATION
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.verification.core.RequestVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import java.time.Instant
import java.util.UUID

class RequestVerifierSpec : StringSpec() {
    override fun listeners(): List<TestListener> = listOf(ReportListener)

    init {
        val incorrectUri = "incorrect/uri"
        val correctUri = "http://correct.uri"
        System.setProperty(TEST_SP_METADATA_PROPERTY,
                Resources.getResource("test-sp-metadata.xml").path)

        "request with correct ID, version and instant should pass" {
            NodeDecorator(Common.buildDom(createRequest())).let {
                RequestVerifierTest(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "request with non-unique ID should fail" {
            NodeDecorator(Common.buildDom(createRequest(id = "id"))).let {
                RequestVerifierTest(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()

            NodeDecorator(Common.buildDom(createRequest(id = "id"))).let {
                RequestVerifierTest(it).verify()
            }
            Report.getExceptionMessages(CORE_1_3).shouldContain(SAMLCore_1_3_4_a.message)
            Report.getExceptionMessages(CORE_3_2).apply {
                this.shouldContain(SAMLCore_1_3_4_a.message)
                this.shouldContain(SAMLCore_3_2_1_a.message)
            }
        }

        "request with incorrect version (empty) should fail" {
            NodeDecorator(Common.buildDom(createRequest(version = ""))).let {
                RequestVerifierTest(it).verify()
            }
            Report.getExceptionMessages(CORE_1_3).shouldContain(SAMLCore_1_3_1_a.message)
            Report.getExceptionMessages(CORE_3_2).apply {
                this.shouldContain(SAMLCore_1_3_1_a.message)
                this.shouldContain(SAMLCore_3_2_1_b.message)
            }
        }

        "request with incorrect instant (non-UTC) should fail" {
            NodeDecorator(Common.buildDom(
                    createRequest(instant = "2018-05-01T06:15:30-07:00"))).let {
                RequestVerifierTest(it).verify()
            }
            Report.getExceptionMessages(CORE_1_3).shouldContain(SAMLCore_1_3_3_a.message)
            Report.getExceptionMessages(CORE_3_2).apply {
                this.shouldContain(SAMLCore_1_3_3_a.message)
                this.shouldContain(SAMLCore_3_2_1_c.message)
            }
        }

        "request with correct destination should pass" {
            NodeDecorator(Common.buildDom(
                    createRequest(attribute = "$DESTINATION=\"$correctUri\""))).let {
                RequestVerifierTest(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "request with incorrect destination should fail" {
            NodeDecorator(Common.buildDom(
                    createRequest(attribute = "$DESTINATION=\"$incorrectUri\""))).let {
                RequestVerifierTest(it).verify()
            }
            Report.getExceptionMessages(CORE_3_2).shouldContain(SAMLCore_3_2_1_e.message)
        }

        "request with correct consent should pass" {
            NodeDecorator(Common.buildDom(
                    createRequest(attribute = "$CONSENT=\"$correctUri\""))).let {
                RequestVerifierTest(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "request with incorrect consent (relative URI) should fail" {
            NodeDecorator(Common.buildDom(
                    createRequest(attribute = "$CONSENT=\"$incorrectUri\""))).let {
                RequestVerifierTest(it).verify()
            }
            Report.getExceptionMessages(CORE_1_3).shouldContain(SAMLCore_1_3_2_a.message)
        }
    }

    private fun createRequest(
        id: String? = UUID.randomUUID().toString().replace("-", ""),
        version: String? = "2.0",
        attribute: String = "",
        instant: String = Instant.now().toString()
    ): String {
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
