/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compilance.verification.core

import io.kotlintest.extensions.TestListener
import io.kotlintest.forAll
import io.kotlintest.matchers.boolean.shouldBeFalse
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.specs.StringSpec
import org.codice.compilance.ReportListener
import org.codice.compliance.Common.Companion.buildDom
import org.codice.compliance.SAMLCore_2_3_3_a
import org.codice.compliance.SAMLCore_3_2_2_c
import org.codice.compliance.SAMLCore_4_1_2_a
import org.codice.compliance.SAMLCore_4_1_3_2_a
import org.codice.compliance.SAMLCore_4_1_3_2_b
import org.codice.compliance.SAMLCore_4_1_3_3_a
import org.codice.compliance.SAMLCore_4_2_a
import org.codice.compliance.Section.CORE_2_3
import org.codice.compliance.Section.CORE_3_2
import org.codice.compliance.Section.CORE_4_1
import org.codice.compliance.Section.CORE_4_2
import org.codice.compliance.report.Report
import org.codice.compliance.utils.ASSERTION_NAMESPACE
import org.codice.compliance.utils.PROTOCOL_NAMESPACE
import org.codice.compliance.verification.core.SamlVersioningVerifier
import java.time.Instant

class SamlVersioningVerifierSpec : StringSpec() {
    override fun listeners(): List<TestListener> = listOf(ReportListener)

    init {
        val now = Instant.now()
        val response = {
            resVersion: String, resNamespace: String?, version: String, namespace: String? ->
            """
            |<s:Response xmlns:s="$resNamespace" ID="id" Version="$resVersion" IssueInstant="$now">
            |  <s:Status>
            |    <s:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
            |  </s:Status>
            |  <s2:Assertion xmlns:s2="$namespace" ID="id" IssueInstant="$now" Version="$version">
            |    <s2:Issuer>https://localhost:8993/services/idp/login</s2:Issuer>
            |  </s2:Assertion>
            |</s:Response>
           """.trimMargin()
        }

        val incorrectVersions = listOf("1.0", "1.1", "3.0", "2")
        val incorrectNamespaces = listOf("incorrect_SAML_namespace",
                "urn:oasis:names:tc:SAML:1.0:protocol", "urn:oasis:names:tc:SAML:3.0:protocol")

        "response with incorrect versions fails" {
            forAll(incorrectVersions) { version ->
                buildDom(response(version, PROTOCOL_NAMESPACE, "2.0", ASSERTION_NAMESPACE)).let {
                    SamlVersioningVerifier(it).verify()
                }
                Report.getExceptionMessages(CORE_3_2).shouldContain(SAMLCore_3_2_2_c.message)
                Report.getExceptionMessages(CORE_4_1).apply {
                    this.shouldContain(SAMLCore_3_2_2_c.message)
                    this.shouldContain(SAMLCore_4_1_3_3_a.message)
                }
                Report.resetExceptionMap()
            }
        }

        "response with a version that is not numeric doesn't error out." {
            buildDom(response("I'm a string", PROTOCOL_NAMESPACE, "2.0", ASSERTION_NAMESPACE)).let {
                SamlVersioningVerifier(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "response with correct version should pass" {
            buildDom(response("2.0", PROTOCOL_NAMESPACE, "2.0", ASSERTION_NAMESPACE)).let {
                SamlVersioningVerifier(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "response with version 1.0 should fail with SAMLCore_4_1_3_2_a" {
            buildDom(response("1.0", PROTOCOL_NAMESPACE, "1.0", ASSERTION_NAMESPACE)).let {
                SamlVersioningVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_4_1).shouldContain(SAMLCore_4_1_3_2_a.message)
        }

        "response with version 3.0 should fail with SAMLCore_4_1_3_2_b" {
            buildDom(response("3.0", PROTOCOL_NAMESPACE, "3.0", ASSERTION_NAMESPACE)).let {
                SamlVersioningVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_4_1).shouldContain(SAMLCore_4_1_3_2_b.message)
        }

        "response with incorrect assertion versions fails" {
            forAll(incorrectVersions) { version ->
                buildDom(response("2.0", PROTOCOL_NAMESPACE, version, ASSERTION_NAMESPACE)).let {
                    SamlVersioningVerifier(it).verify()
                }
                Report.getExceptionMessages(CORE_2_3).shouldContain(SAMLCore_2_3_3_a.message)
                Report.getExceptionMessages(CORE_4_1).apply {
                    this.shouldContain(SAMLCore_2_3_3_a.message)
                    this.shouldContain(SAMLCore_4_1_2_a.message)
                }
                Report.resetExceptionMap()
            }
        }

        "response with correct namespace URIs passes" {
            buildDom(response("2.0", PROTOCOL_NAMESPACE, "2.0", ASSERTION_NAMESPACE)).let {
                SamlVersioningVerifier(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "response with incorrect namespace URIs fails" {
            forAll(incorrectNamespaces) { uri ->
                buildDom(response("2.0", uri, "2.0", ASSERTION_NAMESPACE)).let {
                    SamlVersioningVerifier(it).verify()
                }
                Report.getExceptionMessages(CORE_4_2).shouldContain(SAMLCore_4_2_a.message)
                Report.resetExceptionMap()
            }
        }

        "response with incorrect namespace URIs on the response element fails" {
            forAll(incorrectNamespaces) { uri ->
                buildDom(response("2.0", PROTOCOL_NAMESPACE, "2.0", uri)).let {
                    SamlVersioningVerifier(it).verify()
                }
                Report.getExceptionMessages(CORE_4_2).shouldContain(SAMLCore_4_2_a.message)
                Report.resetExceptionMap()
            }
        }
    }
}
