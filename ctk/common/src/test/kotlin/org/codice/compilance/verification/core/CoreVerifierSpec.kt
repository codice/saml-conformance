/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compilance.verification.core

import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.matchers.string.shouldNotContain
import io.kotlintest.shouldThrow
import io.kotlintest.specs.StringSpec
import io.mockk.every
import io.mockk.mockk
import org.codice.compliance.Common.Companion.buildDom
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCoreRefMessage
import org.codice.compliance.SAMLCore_3_2_1_d
import org.codice.compliance.utils.REQUESTER
import org.codice.compliance.utils.RESPONDER
import org.codice.compliance.verification.core.CoreVerifier
import java.time.Duration
import java.time.Instant

@Suppress("StringLiteralDuplication", "MagicNumber")
class CoreVerifierSpec : StringSpec() {
    init {
        val now = Instant.now()
        val later = now.plus(Duration.ofMinutes(30))

        val response = { statusCode: String ->
            """
                |<s:Response xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" Version="2.0"
                |    IssueInstant="$now">
                |  <s:Status>
                |    <s:StatusCode Value="$statusCode"></s:StatusCode>
                |  </s:Status>
                |</s:Response>
                """.trimMargin()
        }

        val noStatusResponse = {
            """
                |<s:Response xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" Version="2.0"
                |    IssueInstant="$now">
                |</s:Response>
                """.trimMargin()
        }

        val twoStatusResponse = { statusCode1: String, statusCode2: String ->
            """
                |<s:Response xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol" ID="id" Version="2.0"
                |    IssueInstant="$now">
                |  <s:Status>
                |    <s:StatusCode Value="$statusCode1"></s:StatusCode>
                |  </s:Status>
                |  <s:Status>
                |    <s:StatusCode Value="$statusCode2"></s:StatusCode>
                |  </s:Status>
                |</s:Response>
                """.trimMargin()
        }

        val specRefMsg = mockk<SAMLCoreRefMessage>()
        every { specRefMsg.message } returns "test message"
        every { specRefMsg.name } returns "TEST"

        "single error status response has expected code" {
            buildDom(response(REQUESTER)).let {
                CoreVerifier.verifyErrorStatusCodes(it, specRefMsg,
                    expectedStatusCode = REQUESTER)
            }
        }

        "mismatched status code fails and does not contain SAMLCore 3.2.1 response" {
            buildDom(response("urn:samlconf:fail")).let {
                shouldThrow<SAMLComplianceException> {
                    CoreVerifier.verifyErrorStatusCodes(it, specRefMsg,
                        expectedStatusCode = "urn:samlconf:expected")
                }.message?.shouldNotContain(SAMLCore_3_2_1_d.message)
            }
        }

        "mismatch with expected code of REQUESTER includes SAMLCore 3.2.1 response" {
            buildDom(response(RESPONDER)).let {
                shouldThrow<SAMLComplianceException> {
                    CoreVerifier.verifyErrorStatusCodes(it, specRefMsg,
                        expectedStatusCode = REQUESTER)
                }.message?.shouldContain(SAMLCore_3_2_1_d.message)
            }
        }

        "response with no status blocks" {
            val statusCode = "urn:samlconf:fail"
            buildDom(noStatusResponse()).let {
                shouldThrow<SAMLComplianceException> {
                    CoreVerifier.verifyErrorStatusCodes(it, specRefMsg,
                        expectedStatusCode = statusCode)
                }
            }
        }

        "response with multiple status blocks" {
            val statusCode = "urn:samlconf:fail"
            buildDom(twoStatusResponse("urn:samlconf:fail", "urn:samlconf:fail")).let {
                shouldThrow<SAMLComplianceException> {
                    CoreVerifier.verifyErrorStatusCodes(it, specRefMsg,
                        expectedStatusCode = statusCode)
                }
            }
        }

        "validateTimeWindow with null datetime attributes" {
            buildDom("<fld>this is garbage</fld>").let {
                CoreVerifier.validateTimeWindow(it, specRefMsg)
            }

            buildDom("""<fld NotBefore="$now"/>""").let {
                CoreVerifier.validateTimeWindow(it, specRefMsg)
            }

            buildDom("""<fld NotOnOrAfter="$now"/>""").let {
                CoreVerifier.validateTimeWindow(it, specRefMsg)
            }

            buildDom("""<fld NotBefore="$later"/>""").let {
                CoreVerifier.validateTimeWindow(it, specRefMsg)
            }

            buildDom("""<fld NotOnOrAfter="$later"/>""").let {
                CoreVerifier.validateTimeWindow(it, specRefMsg)
            }
        }

        "validateTimeWindow with correct datetime attributes" {
            buildDom("""<fld NotBefore="$now" NotOnOrAfter="$later"/>""").let {
                CoreVerifier.validateTimeWindow(it, specRefMsg)
            }
        }

        "validateTimeWindow with incorrect datetime attributes" {
            buildDom("""<fld NotBefore="$later" NotOnOrAfter="$now"/>""").let {
                shouldThrow<SAMLComplianceException> {
                    CoreVerifier.validateTimeWindow(it, specRefMsg)
                }
            }

            buildDom("""<fld NotBefore="$now" NotOnOrAfter="$now"/>""").let {
                shouldThrow<SAMLComplianceException> {
                    CoreVerifier.validateTimeWindow(it, specRefMsg)
                }
            }

            buildDom("""<fld NotBefore="$later" NotOnOrAfter="$later"/>""").let {
                shouldThrow<SAMLComplianceException> {
                    CoreVerifier.validateTimeWindow(it, specRefMsg)
                }
            }
        }
    }
}
