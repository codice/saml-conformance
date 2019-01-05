/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compilance.verification.core

import io.kotlintest.extensions.TestListener
import io.kotlintest.matchers.boolean.shouldBeFalse
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.specs.StringSpec
import org.codice.compilance.ReportListener
import org.codice.compliance.Common.Companion.buildDom
import org.codice.compliance.SAMLCore_8_2_2_a
import org.codice.compliance.SAMLCore_8_2_3_a
import org.codice.compliance.SAMLCore_8_3_2_a
import org.codice.compliance.SAMLCore_8_3_6_a
import org.codice.compliance.SAMLCore_8_3_6_b
import org.codice.compliance.SAMLCore_8_3_7_a
import org.codice.compliance.SAMLCore_8_3_7_d
import org.codice.compliance.SAMLCore_8_3_8_a
import org.codice.compliance.report.Report
import org.codice.compliance.report.Report.Section.CORE_8_2
import org.codice.compliance.report.Report.Section.CORE_8_3
import org.codice.compliance.utils.ASSERTION_NAMESPACE
import org.codice.compliance.utils.ENTITY
import org.codice.compliance.utils.PERSISTENT_ID
import org.codice.compliance.utils.PROTOCOL_NAMESPACE
import org.codice.compliance.utils.TRANSIENT_ID
import org.codice.compliance.utils.VERSION
import org.codice.compliance.verification.core.SamlDefinedIdentifiersVerifier
import org.codice.compliance.verification.core.SamlDefinedIdentifiersVerifier.Companion.ATTRIBUTE_NAME_FORMAT_BASIC
import org.codice.compliance.verification.core.SamlDefinedIdentifiersVerifier.Companion.ATTRIBUTE_NAME_FORMAT_UNSPECIFIED
import org.codice.compliance.verification.core.SamlDefinedIdentifiersVerifier.Companion.ATTRIBUTE_NAME_FORMAT_URI
import org.codice.compliance.verification.core.SamlDefinedIdentifiersVerifier.Companion.ENTITY_ID_MAX_LEN
import org.codice.compliance.verification.core.SamlDefinedIdentifiersVerifier.Companion.ID_VALUE_LENGTH_LIMIT
import org.codice.compliance.verification.core.SamlDefinedIdentifiersVerifier.Companion.NAME_ID_FORMAT_EMAIL
import org.w3c.dom.Node
import java.time.Instant

@Suppress("StringLiteralDuplication")
class SamlDefinedIdentifiersVerifierSpec : StringSpec() {
    override fun listeners(): List<TestListener> = listOf(ReportListener)

    init {
        val validEntityId = "ValidEntityID"
        val maxLengthEntityId = "A".repeat(ENTITY_ID_MAX_LEN)
        val maxLengthPersistentId = "A".repeat(ID_VALUE_LENGTH_LIMIT)

        val now = Instant.now()

        @Suppress("LongParameterList")
        fun createResponse(
            attributeName: String = "Unspecified",
            attributeFormat: String = ATTRIBUTE_NAME_FORMAT_UNSPECIFIED,
            identifierValue: String = "example-email@domain.com",
            identifierFormat: String = NAME_ID_FORMAT_EMAIL,
            extraIdentifierAttribute: String = ""
        ): Node {
            return buildDom(
                    """
                    |<samlp:Response
                    |  xmlns:saml="$ASSERTION_NAMESPACE"
                    |  xmlns:samlp="$PROTOCOL_NAMESPACE"
                    |  ID="id"
                    |  Version="$VERSION"
                    |  IssueInstant="$now">
                    |  <samlp:Status>
                    |    <samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/>
                    |  </samlp:Status>
                    |  <saml:Assertion ID="id" IssueInstant="$now" Version="$VERSION">
                    |    <saml:Issuer
                    |    $extraIdentifierAttribute
                    |    Format="$identifierFormat">$identifierValue</saml:Issuer>
                    |    <saml:AttributeStatement>
                    |      <saml:Attribute Name="$attributeName" NameFormat="$attributeFormat" />
                    |    </saml:AttributeStatement>
                    |  </saml:Assertion>
                    |</samlp:Response>
                    """.trimMargin())
        }

        /* 8.2 URI/Basic name attribute formats */
        "valid 'unspecified' attribute name" {
            createResponse(
                    attributeName = "Unspecified Name",
                    attributeFormat = ATTRIBUTE_NAME_FORMAT_UNSPECIFIED).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        // No invalid test for 'unspecified' format; other than what is allowed in xml

        "valid URI attribute name" {
            createResponse(
                    attributeName = "validURI.com",
                    attributeFormat = ATTRIBUTE_NAME_FORMAT_URI).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "invalid URI attribute name" {
            createResponse(
                    attributeName = "Whitespace Not Allowed In URI",
                    attributeFormat = ATTRIBUTE_NAME_FORMAT_URI).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_2).shouldContain(SAMLCore_8_2_2_a.message)
        }

        "valid Basic attribute name" {
            createResponse(
                    attributeName = "BasicName",
                    attributeFormat = ATTRIBUTE_NAME_FORMAT_BASIC).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "null (defaults to 'unspecified') attribute format" {
            createResponse(
                    attributeName = "This string is only allowed in an 'unspecified' name format",
                    attributeFormat = "").let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "invalid Basic attribute name" {
            createResponse(
                    attributeName = "Whitespace Not Allowed In Attribute Name",
                    attributeFormat = ATTRIBUTE_NAME_FORMAT_BASIC).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_2).shouldContain(SAMLCore_8_2_3_a.message)
        }

        /* 8.3.2 Email Address */
        "valid Email name identifier".config(enabled = false) {
            createResponse(
                    identifierValue = "example-email@domain.com",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "invalid Email name identifier (multiple '@'s)".config(enabled = false) {
            createResponse(
                    identifierValue = "example@email@domain.com",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_2_a.message)
        }

        "invalid Email name identifier (no '@')".config(enabled = false) {
            createResponse(
                    identifierValue = "example-email.domain.com",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_2_a.message)
        }

        "invalid Email name identifier (no '.com')".config(enabled = false) {
            createResponse(
                    identifierValue = "example-email@domain",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_2_a.message)
        }

        "invalid Email name identifier (end with '.')".config(enabled = false) {
            createResponse(
                    identifierValue = "example-email@domain.",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_2_a.message)
        }

        "invalid Email name identifier (single word)".config(enabled = false) {
            createResponse(
                    identifierValue = "exampleemaildomaincom",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_2_a.message)
        }

        "invalid Email name identifier (whitespace)".config(enabled = false) {
            createResponse(
                    identifierValue = "example email@domain.com",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_2_a.message)
        }

        "invalid Email name identifier (invalid characters)".config(enabled = false) {
            createResponse(
                    identifierValue = "example:email@domain.com",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_2_a.message)
        }

        "invalid Email name identifier (comment)".config(enabled = false) {
            createResponse(
                    identifierValue = "example.email@domain.com(comment)",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_2_a.message)
        }

        "invalid Email name identifier (surrounded by '<' and '>')".config(enabled = false) {
            createResponse(
                    identifierValue = "&lt;example.email@domain.com&gt;",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_2_a.message)
        }

        /* 8.3.6 Entity Identifier */
        "valid Entity name identifier" {
            createResponse(
                    identifierValue = validEntityId,
                    identifierFormat = ENTITY).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "invalid NameQualifier attribute on Entity name identifier" {
            createResponse(
                    identifierValue = validEntityId,
                    identifierFormat = ENTITY,
                    extraIdentifierAttribute = """NameQualifier="$validEntityId"""").let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_6_a.message)
        }

        "invalid SPNameQualifier attribute on Entity name identifier" {
            createResponse(
                    identifierValue = validEntityId,
                    identifierFormat = ENTITY,
                    extraIdentifierAttribute = """SPNameQualifier="$validEntityId"""").let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_6_a.message)
        }

        "invalid SPProvidedID attribute on Entity name identifier" {
            createResponse(
                    identifierValue = validEntityId,
                    identifierFormat = ENTITY,
                    extraIdentifierAttribute = """SPProvidedID="$validEntityId"""").let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_6_a.message)
        }

        "valid length Entity name identifier" {
            createResponse(
                    identifierValue = maxLengthEntityId,
                    identifierFormat = ENTITY).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "invalid length Entity name identifier" {
            createResponse(
                    identifierValue = maxLengthEntityId + "A",
                    identifierFormat = ENTITY).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_6_b.message)
        }

        /* 8.3.7 Persistent Identifier */
        "valid length Persistent Identifier" {
            createResponse(
                    identifierFormat = PERSISTENT_ID,
                    identifierValue = maxLengthPersistentId).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "invalid length Persistent Identifier" {
            createResponse(
                    identifierFormat = PERSISTENT_ID,
                    identifierValue = maxLengthPersistentId + "A").let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_7_a.message)
        }

        "valid SPNameQualifier attribute on Persistent Identifier" {
            createResponse(identifierFormat = PERSISTENT_ID,
                    extraIdentifierAttribute =
                    "SPNameQualifier=\"https://samlhost:8993/services/saml\"").let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "invalid SPNameQualifier attribute on Persistent Identifier" {
            createResponse(identifierFormat = PERSISTENT_ID,
                    extraIdentifierAttribute =
                    "SPNameQualifier=\"https://invalid:8993/sp/name/qualifier\"").let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_7_d.message)
        }

        /* 8.3.8 Transient Identifier */
        "valid length Transient Identifier" {
            createResponse(
                    identifierFormat = TRANSIENT_ID,
                    identifierValue = maxLengthPersistentId).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.hasExceptions().shouldBeFalse()
        }

        "invalid length Transient Identifier" {
            createResponse(
                    identifierFormat = TRANSIENT_ID,
                    identifierValue = maxLengthPersistentId + "A").let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
            Report.getExceptionMessages(CORE_8_3).shouldContain(SAMLCore_8_3_8_a.message)
        }
    }
}
