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
package org.codice.compilance.verification.profile

import com.google.common.io.Resources
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.shouldThrow
import io.kotlintest.specs.StringSpec
import org.codice.compliance.Common
import org.codice.compliance.IMPLEMENTATION_PATH
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_4_4_3_3_a
import org.codice.compliance.SAMLProfiles_4_4_3_5_a
import org.codice.compliance.SAMLProfiles_4_4_4_1_a
import org.codice.compliance.SAMLProfiles_4_4_4_1_b
import org.codice.compliance.SAMLProfiles_4_4_4_1_c
import org.codice.compliance.SAMLProfiles_4_4_4_2_a
import org.codice.compliance.SAMLProfiles_4_4_4_2_b
import org.codice.compliance.utils.NodeWrapper
import org.codice.compliance.verification.profile.SingleLogoutProfileVerifier
import java.time.Instant

class SingleLogoutProfileVerifierSpec : StringSpec() {
    private val correctIdpIssuer = "http://correct.idp.issuer"
    private val incorrectIdpIssuer = "incorrect/idp/issuer"
    private val correctNameIDValue = "admin"
    private val incorrectNameIDValue = "incorrect"
    @Suppress("StringLiteralDuplication")
    private val ssoResponse = Common.buildDom("""
            |<s:Response xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
            | xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion"
            | xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
            | xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
            | xmlns:dsig="http://www.w3.org/2000/09/xmldsig#"
            | Version="2.0"
            | IssueInstant="${Instant.now()}">
            |  <s2:Issuer>http://correct.idp.issuer</s2:Issuer>
            |  <s2:Assertion>
            |    <s2:Issuer>http://correct.idp.issuer</s2:Issuer>
            |    <s2:Subject>${createNameID(correctNameIDValue)}</s2:Subject>
            |    <s2:AuthnStatement SessionIndex="0"/>
            |    <s2:Conditions>
            |      <s2:AudienceRestriction>
            |        <s2:Audience>https://samlhost:8993/services/saml</s2:Audience>
            |      </s2:AudienceRestriction>
            |    </s2:Conditions>
            |  </s2:Assertion>
            |</s:Response>
           """.trimMargin())

    init {
        System.setProperty(IMPLEMENTATION_PATH,
                Resources.getResource("implementation").path)

        "logout request with correct issuer should pass" {
            NodeWrapper(Common.buildDom(createLogoutRequest(correctIdpIssuer)),
                    isSigned = true).let {
                SingleLogoutProfileVerifier(it).verifyLogoutRequest(ssoResponse)
            }
        }

        "verify logout request with logout response should fail" {
            NodeWrapper(Common.buildDom(createLogoutResponse(incorrectIdpIssuer)),
                    isSigned = true).let {
                shouldThrow<SAMLComplianceException> {
                    SingleLogoutProfileVerifier(it).verifyLogoutRequest(ssoResponse)
                }.message?.shouldContain(SAMLProfiles_4_4_3_3_a.message)
            }
        }

        "unsigned logout request should fail" {
            NodeWrapper(Common.buildDom(createLogoutRequest(correctIdpIssuer)),
                    isSigned = false).let {
                shouldThrow<SAMLComplianceException> {
                    SingleLogoutProfileVerifier(it).verifyLogoutRequest(ssoResponse)
                }.message?.shouldContain(SAMLProfiles_4_4_4_1_b.message)
            }
        }

        "logout request with incorrect issuer should fail" {
            NodeWrapper(Common.buildDom(createLogoutRequest(incorrectIdpIssuer)),
                    isSigned = true).let {
                shouldThrow<SAMLComplianceException> {
                    SingleLogoutProfileVerifier(it).verifyLogoutRequest(ssoResponse)
                }.message?.shouldContain(SAMLProfiles_4_4_4_1_a.message)
            }
        }

        "logout request with non-matching NameID should fail" {
            NodeWrapper(
                    Common.buildDom(createLogoutRequest(correctIdpIssuer, incorrectNameIDValue)),
                    isSigned = true).let {
                shouldThrow<SAMLComplianceException> {
                    SingleLogoutProfileVerifier(it).verifyLogoutRequest(ssoResponse)
                }.message?.shouldContain(SAMLProfiles_4_4_4_1_c.message)
            }
        }

        "logout response with correct issuer should pass" {
            NodeWrapper(Common.buildDom(createLogoutResponse(correctIdpIssuer)),
                    isSigned = true).let {
                SingleLogoutProfileVerifier(it).verifyLogoutResponse()
            }
        }

        "verify logout response with logout request should fail" {
            NodeWrapper(Common.buildDom(createLogoutRequest(incorrectIdpIssuer)),
                    isSigned = true).let {
                shouldThrow<SAMLComplianceException> {
                    SingleLogoutProfileVerifier(it).verifyLogoutResponse()
                }.message?.shouldContain(SAMLProfiles_4_4_3_5_a.message)
            }
        }

        "unsigned logout response should fail" {
            NodeWrapper(Common.buildDom(createLogoutResponse(correctIdpIssuer)),
                    isSigned = false).let {
                shouldThrow<SAMLComplianceException> {
                    SingleLogoutProfileVerifier(it).verifyLogoutResponse()
                }.message?.shouldContain(SAMLProfiles_4_4_4_2_b.message)
            }
        }

        "logout response with incorrect issuer should fail" {
            NodeWrapper(Common.buildDom(createLogoutResponse(incorrectIdpIssuer)),
                    isSigned = true).let {
                shouldThrow<SAMLComplianceException> {
                    SingleLogoutProfileVerifier(it).verifyLogoutResponse()
                }.message?.shouldContain(SAMLProfiles_4_4_4_2_a.message)
            }
        }
    }

    private fun createLogoutResponse(issuer: String): String {
        return """
            |<s:LogoutResponse
            |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
            |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion">
            |  <s2:Issuer>$issuer</s2:Issuer>
            |</s:LogoutResponse>
           """.trimMargin()
    }

    private fun createLogoutRequest(issuer: String,
                                    nameIDValue: String = correctNameIDValue): String {
        return """
            |<s:LogoutRequest
            |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
            |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion">
            |  <s2:Issuer>$issuer</s2:Issuer>
            |  ${createNameID(nameIDValue)}
            |</s:LogoutRequest>
           """.trimMargin()
    }

    /*
     * Can't use raw string with trimMargin() because we are comparing equality of string values
     * and new lines and spaces mess up that comparison.
     */
    private fun createNameID(nameIDValue: String): String {
        return "<s2:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent\">" +
                nameIDValue +
                "</s2:NameID>"
    }
}
