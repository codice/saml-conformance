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
import org.codice.compliance.Common.Companion.buildDom
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_8_2_2_a
import org.codice.compliance.SAMLCore_8_2_3_a
import org.codice.compliance.SAMLCore_8_3_2_a
import org.codice.compliance.SAMLCore_8_3_6_a
import org.codice.compliance.SAMLCore_8_3_6_b
import org.codice.compliance.SAMLCore_8_3_7_a
import org.codice.compliance.SAMLCore_8_3_7_d
import org.codice.compliance.SAMLCore_8_3_8_a
import org.codice.compliance.utils.TestCommon.Companion.ASSERTION_NAMESPACE
import org.codice.compliance.utils.TestCommon.Companion.ENTITY
import org.codice.compliance.utils.TestCommon.Companion.PERSISTENT_ID
import org.codice.compliance.utils.TestCommon.Companion.PROTOCOL_NAMESPACE
import org.codice.compliance.utils.TestCommon.Companion.TRANSIENT_ID
import org.codice.compliance.utils.TestCommon.Companion.VERSION
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
    init {
        val validEntityId = "ValidEntityID"
        val maxLengthEntityId = "A".repeat(ENTITY_ID_MAX_LEN)
        val maxLengthPersistentId = "A".repeat(ID_VALUE_LENGTH_LIMIT)

        val now = Instant.now()

        @Suppress("LongParameterList")
        fun createResponse(attributeName: String = "Unspecified",
                           attributeFormat: String = ATTRIBUTE_NAME_FORMAT_UNSPECIFIED,
                           identifierValue: String = "example-email@domain.com",
                           identifierFormat: String = NAME_ID_FORMAT_EMAIL,
                           extraIdentifierAttribute: String = ""): Node {
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
        }

        // No invalid test for 'unspecified' format; other than what is allowed in xml

        "valid URI attribute name" {
            createResponse(
                    attributeName = "validURI.com",
                    attributeFormat = ATTRIBUTE_NAME_FORMAT_URI).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
        }

        "invalid URI attribute name" {
            createResponse(
                    attributeName = "Whitespace Not Allowed In URI",
                    attributeFormat = ATTRIBUTE_NAME_FORMAT_URI).let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_2_2_a.message)
            }
        }

        "valid Basic attribute name" {
            createResponse(
                    attributeName = "BasicName",
                    attributeFormat = ATTRIBUTE_NAME_FORMAT_BASIC).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
        }

        "null (defaults to 'unspecified') attribute format" {
            createResponse(
                    attributeName = "This string is only allowed in an 'unspecified' name format",
                    attributeFormat = "").let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
        }

        "invalid Basic attribute name" {
            createResponse(
                    attributeName = "Whitespace Not Allowed In Attribute Name",
                    attributeFormat = ATTRIBUTE_NAME_FORMAT_BASIC).let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_2_3_a.message)
            }
        }

        /* 8.3.2 Email Address */
        "valid Email name identifier" {
            createResponse(
                    identifierValue = "example-email@domain.com",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
        }

        "invalid Email name identifier (multiple '@'s)" {
            createResponse(
                    identifierValue = "example@email@domain.com",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_2_a.message)
            }
        }

        "invalid Email name identifier (no '@')" {
            createResponse(
                    identifierValue = "example-email.domain.com",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_2_a.message)
            }
        }

        "invalid Email name identifier (no '.com')" {
            createResponse(
                    identifierValue = "example-email@domain",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_2_a.message)
            }
        }

        "invalid Email name identifier (end with '.')" {
            createResponse(
                    identifierValue = "example-email@domain.",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_2_a.message)
            }
        }

        "invalid Email name identifier (single word)" {
            createResponse(
                    identifierValue = "exampleemaildomaincom",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_2_a.message)
            }
        }

        "invalid Email name identifier (whitespace)" {
            createResponse(
                    identifierValue = "example email@domain.com",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_2_a.message)
            }
        }

        "invalid Email name identifier (invalid characters)" {
            createResponse(
                    identifierValue = "example:email@domain.com",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_2_a.message)
            }
        }

        "invalid Email name identifier (comment)" {
            createResponse(
                    identifierValue = "example.email@domain.com(comment)",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_2_a.message)
            }
        }

        "invalid Email name identifier (surrounded by '<' and '>')" {
            createResponse(
                    identifierValue = "&lt;example.email@domain.com&gt;",
                    identifierFormat = NAME_ID_FORMAT_EMAIL).let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_2_a.message)
            }
        }

        /* 8.3.6 Entity Identifier */
        "valid Entity name identifier" {
            createResponse(
                    identifierValue = validEntityId,
                    identifierFormat = ENTITY).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
        }

        "invalid NameQualifier attribute on Entity name identifier" {
            createResponse(
                    identifierValue = validEntityId,
                    identifierFormat = ENTITY,
                    extraIdentifierAttribute = """NameQualifier="$validEntityId"""").let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_6_a.message)
            }
        }

        "invalid SPNameQualifier attribute on Entity name identifier" {
            createResponse(
                    identifierValue = validEntityId,
                    identifierFormat = ENTITY,
                    extraIdentifierAttribute = """SPNameQualifier="$validEntityId"""").let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_6_a.message)
            }
        }

        "invalid SPProvidedID attribute on Entity name identifier" {
            createResponse(
                    identifierValue = validEntityId,
                    identifierFormat = ENTITY,
                    extraIdentifierAttribute = """SPProvidedID="$validEntityId"""").let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_6_a.message)
            }
        }

        "valid length Entity name identifier" {
            createResponse(
                    identifierValue = maxLengthEntityId,
                    identifierFormat = ENTITY).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
        }

        "invalid length Entity name identifier" {
            createResponse(
                    identifierValue = maxLengthEntityId + "A",
                    identifierFormat = ENTITY).let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_6_b.message)
            }
        }

        /* 8.3.7 Persistent Identifier */
        "valid length Persistent Identifier" {
            createResponse(
                identifierFormat = PERSISTENT_ID,
                identifierValue = maxLengthPersistentId).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
        }

        "invalid length Persistent Identifier" {
            createResponse(
                identifierFormat = PERSISTENT_ID,
                identifierValue = maxLengthPersistentId + "A").let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_7_a.message)
            }
        }

        "valid SPNameQualifier attribute on Persistent Identifier" {
            createResponse(identifierFormat = PERSISTENT_ID,
                extraIdentifierAttribute =
                "SPNameQualifier=\"https://samlhost:8993/services/saml\"").let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
        }

        "invalid SPNameQualifier attribute on Persistent Identifier" {
            createResponse(identifierFormat = PERSISTENT_ID,
                extraIdentifierAttribute =
                "SPNameQualifier=\"https://invalid:8993/sp/name/qualifier\"").let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_7_d.message)
            }
        }

        /* 8.3.8 Transient Identifier */
        "valid length Transient Identifier" {
            createResponse(
                identifierFormat = TRANSIENT_ID,
                identifierValue = maxLengthPersistentId).let {
                SamlDefinedIdentifiersVerifier(it).verify()
            }
        }

        "invalid length Transient Identifier" {
            createResponse(
                identifierFormat = TRANSIENT_ID,
                identifierValue = maxLengthPersistentId + "A").let {
                shouldThrow<SAMLComplianceException> {
                    SamlDefinedIdentifiersVerifier(it).verify()
                }.message?.shouldContain(SAMLCore_8_3_8_a.message)
            }
        }
    }
}
