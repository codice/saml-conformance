/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compilance.verification.core

import io.kotlintest.forAll
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.shouldThrow
import io.kotlintest.specs.StringSpec
import org.codice.compliance.Common.Companion.buildDom
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_1_3_1_a
import org.codice.compliance.SAMLCore_1_3_2_a
import org.codice.compliance.SAMLCore_1_3_3_a
import org.codice.compliance.SAMLCore_1_3_4_a
import org.codice.compliance.SAMLCore_3_4_1_1_a
import org.codice.compliance.SAMLSpecRefMessage
import org.codice.compliance.verification.core.CommonDataTypeVerifier
import org.w3c.dom.Node

@Suppress("StringLiteralDuplication" /* Small duplicate test strings */)
class CommonDataTypeVerifierSpec : StringSpec() {
    init {
        "null or blank string value fails" {
            forAll(listOf(null, "", "   ")) {
                badString(it)
                badString(it, SAMLCore_3_4_1_1_a)
            }
        }

        "valid string value passes" {
            forAll(listOf("a", "abc", "whatever\nyou say")) {
                CommonDataTypeVerifier.verifyStringValue(buildDom("<fld>$it</fld>"))
                CommonDataTypeVerifier.verifyStringValue(buildDom("<fld>$it</fld>"),
                        SAMLCore_3_4_1_1_a)
            }
        }

        "bad Uri value fails" {
            forAll(listOf(null, "", "   ", "/not/absolute")) {
                badUri(it)
                badUri(it, SAMLCore_3_4_1_1_a)
            }
        }

        "null Uri node fails" {
            nullNodeFails(expectedErr = SAMLCore_1_3_2_a,
                    func = CommonDataTypeVerifier.Companion::verifyUriValue)
            nullNodeFails(SAMLCore_1_3_2_a,
                    SAMLCore_3_4_1_1_a,
                    CommonDataTypeVerifier.Companion::verifyUriValue)
        }

        "absolute Uri passes" {
            buildDom("<fld>http://foo.bar</fld>").let {
                CommonDataTypeVerifier.verifyUriValue(it)
            }
            buildDom("<fld>http://foo.bar/subpath</fld>").let {
                CommonDataTypeVerifier.verifyUriValue(it, SAMLCore_3_4_1_1_a)
            }
            buildDom("<fld>protocolX://foo.bar/subpath</fld>").let {
                CommonDataTypeVerifier.verifyUriValue(it, SAMLCore_3_4_1_1_a)
            }
        }

        "null dateTime node fails" {
            nullNodeFails(expectedErr = SAMLCore_1_3_3_a,
                    func = CommonDataTypeVerifier.Companion::verifyDateTimeValue)
            nullNodeFails(SAMLCore_1_3_3_a,
                    SAMLCore_3_4_1_1_a,
                    CommonDataTypeVerifier.Companion::verifyDateTimeValue)
        }

        "dateTime not in UTC fails" {
            badInput("2018-05-01T06:15:30-07:00",
                    expectedErr = SAMLCore_1_3_3_a,
                    func = CommonDataTypeVerifier.Companion::verifyDateTimeValue)
            badInput("2018-05-01T06:15:30-07:00",
                    SAMLCore_1_3_3_a,
                    SAMLCore_3_4_1_1_a,
                    CommonDataTypeVerifier.Companion::verifyDateTimeValue)
        }

        "dateTime in UTC passes" {
            buildDom("<fld>2018-05-01T13:15:30Z</fld>").let {
                CommonDataTypeVerifier.verifyDateTimeValue(it)
                CommonDataTypeVerifier.verifyDateTimeValue(it, SAMLCore_3_4_1_1_a)
            }
        }

        "null id node fails" {
            nullNodeFails(expectedErr = SAMLCore_1_3_4_a,
                    func = CommonDataTypeVerifier.Companion::verifyIdValue)
            nullNodeFails(SAMLCore_1_3_4_a,
                    SAMLCore_3_4_1_1_a,
                    CommonDataTypeVerifier.Companion::verifyIdValue)
        }

        "null, blank, and good id values pass; duplicates fail" {
            buildDom("<fld/>").let {
                CommonDataTypeVerifier.verifyIdValue(it)
            }
            buildDom("<fld>   </fld>").let {
                CommonDataTypeVerifier.verifyIdValue(it, SAMLCore_3_4_1_1_a)
            }
            buildDom("<fld>this is my id</fld>").let {
                CommonDataTypeVerifier.verifyIdValue(it, SAMLCore_3_4_1_1_a)
            }

            buildDom("<fld/>").let {
                shouldThrow<SAMLComplianceException> {
                    CommonDataTypeVerifier.verifyIdValue(it)
                }.message?.shouldContain(SAMLCore_1_3_4_a.message)
            }
            buildDom("<fld>   </fld>").let {
                val expectedExc = shouldThrow<SAMLComplianceException> {
                    CommonDataTypeVerifier.verifyIdValue(it, SAMLCore_3_4_1_1_a)
                }
                expectedExc.message?.shouldContain(SAMLCore_1_3_4_a.message)
                expectedExc.message?.shouldContain(SAMLCore_3_4_1_1_a.message)
            }
            buildDom("<fld>this is my id</fld>").let {
                val expectedExc = shouldThrow<SAMLComplianceException> {
                    CommonDataTypeVerifier.verifyIdValue(it, SAMLCore_3_4_1_1_a)
                }
                expectedExc.message?.shouldContain(SAMLCore_1_3_4_a.message)
                expectedExc.message?.shouldContain(SAMLCore_3_4_1_1_a.message)
            }
        }

        "branching logic works correctly" {
            fun makeInput(id1: String, id2: String): Node {
                val goodInput = """
                  |<foo xmlns:test="http://www.w3.org/2001/XMLSchema-instance">
                  |  <bar>
                  |    <aString test:type="string">hello world</aString>
                  |    <anUri test:type="anyURI">http://foo.bar</anUri>
                  |    <aDateTime test:type="dateTime">2018-05-01T13:15:30Z</aDateTime>
                  |    <anId test:type="ID">$id1</anId>
                  |    <baz>
                  |      <anId test:type="ID">$id2</anId>
                  |    </baz>
                  |  </bar>
                  |</foo>
                  """.trimMargin()

                return buildDom(goodInput)
            }

            makeInput("id1", "id2").let {
                CommonDataTypeVerifier.verifyCommonDataType(it)
            }

            // Check for duplicate id
            makeInput("id1", "id4").let {
                shouldThrow<SAMLComplianceException> {
                    CommonDataTypeVerifier.verifyCommonDataType(it)
                }.message?.shouldContain(SAMLCore_1_3_4_a.message)
            }
        }
    }

    private fun nullNodeFails(
        expectedErr: SAMLSpecRefMessage,
        extraError: SAMLSpecRefMessage? = null,
        func: (node: Node?, extraErr: SAMLSpecRefMessage?) -> Any
    ) {
        val expectedExcWithExtraError = shouldThrow<SAMLComplianceException> {
            func(null as Node?, extraError)
        }
        expectedExcWithExtraError.message?.shouldContain(expectedErr.message)
        extraError?.let {
            expectedExcWithExtraError.message?.shouldContain(extraError.message)
        }
    }

    private fun badInput(
        input: String?,
        expectedErr: SAMLSpecRefMessage,
        extraError: SAMLSpecRefMessage? = null,
        func: (node: Node, extraErr: SAMLSpecRefMessage?) -> Any
    ) {
        val domString = if (input == null) "<fld/>" else "<fld>$input</fld>"
        buildDom(domString).let {
            val expectedExc = shouldThrow<SAMLComplianceException> {
                func(it, extraError)
            }
            expectedExc.message?.shouldContain(expectedErr.message)
            extraError?.let {
                expectedExc.message?.shouldContain(extraError.message)
            }
        }
    }

    private fun badString(input: String?, extraError: SAMLSpecRefMessage? = null) {
        badInput(input,
                SAMLCore_1_3_1_a,
                extraError,
                CommonDataTypeVerifier.Companion::verifyStringValue)
    }

    private fun badUri(input: String?, extraError: SAMLSpecRefMessage? = null) {
        badInput(input,
                SAMLCore_1_3_2_a,
                extraError,
                CommonDataTypeVerifier.Companion::verifyUriValue)
    }
}
