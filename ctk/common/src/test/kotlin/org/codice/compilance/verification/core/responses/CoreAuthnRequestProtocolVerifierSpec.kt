/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compilance.verification.core.responses

import io.kotlintest.extensions.TestListener
import io.kotlintest.forAll
import io.kotlintest.matchers.boolean.shouldBeFalse
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.specs.StringSpec
import org.codice.compilance.ReportListener
import org.codice.compliance.Common
import org.codice.compliance.SAMLCore_3_3_2_2_1_a
import org.codice.compliance.report.Report
import org.codice.compliance.Section.CORE_3_3
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.utils.ddfAuthnContextList
import org.codice.compliance.verification.core.responses.CoreAuthnRequestProtocolVerifier
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import java.time.Instant
import java.util.UUID

class CoreAuthnRequestProtocolVerifierSpec : StringSpec() {
    override fun listeners(): List<TestListener> = listOf(ReportListener)

    val response = { authnContextClassRef: String? ->
        """
            |<s:Response
            |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
            |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
            |ID="${"a" + UUID.randomUUID().toString()}"
            |Version="2.0"
            |IssueInstant="${Instant.now()}">
            |  <s2:Assertion>
            |    <s2:AuthnStatement>
            |      <s2:AuthnContext>
            |        <s2:AuthnContextClassRef>$authnContextClassRef</s2:AuthnContextClassRef>
            |      </s2:AuthnContext>
            |    </s2:AuthnStatement>
            |  </s2:Assertion>
            |</s:Response>
           """.trimMargin()
    }

    init {
        "response with correct AuthnContextClassRef passes" {
            forAll(ddfAuthnContextList) { authContext ->
                NodeDecorator(Common.buildDom(response(authContext))).let {
                    CoreAuthnRequestProtocolVerifier(AuthnRequestBuilder().buildObject(), it)
                            .verifyAuthnContextClassRef()
                }
                Report.hasExceptions().shouldBeFalse()
            }
        }

        "response with incorrect AuthnContextClassRef fails" {
            forAll(listOf("wrong", "", null)) { authContext ->
                NodeDecorator(Common.buildDom(response(authContext))).let {
                    CoreAuthnRequestProtocolVerifier(AuthnRequestBuilder().buildObject(), it)
                            .verifyAuthnContextClassRef()
                }
                Report.getExceptionMessages(CORE_3_3).shouldContain(SAMLCore_3_3_2_2_1_a.message)
                Report.resetExceptionMap()
            }
        }

        "response with no AuthnContextClassRef passes" {
            val responseWithNoAuthnContextClassRef = """
                |<s:Response
                |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
                |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
                |ID="${"a" + UUID.randomUUID().toString()}"
                |Version="2.0"
                |IssueInstant="${Instant.now()}">
                |  <s2:Assertion>
                |    <s2:AuthnStatement>
                |      <s2:AuthnContext/>
                |    </s2:AuthnStatement>
                |  </s2:Assertion>
                |</s:Response>
               """.trimMargin()
            NodeDecorator(Common.buildDom(responseWithNoAuthnContextClassRef)).let {
                CoreAuthnRequestProtocolVerifier(AuthnRequestBuilder().buildObject(), it)
                        .verifyAuthnContextClassRef()
            }
        }
    }
}
