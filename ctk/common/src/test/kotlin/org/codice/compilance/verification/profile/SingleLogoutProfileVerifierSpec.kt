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
import org.codice.compliance.SAMLProfiles_4_4_4_1_a
import org.codice.compliance.SAMLProfiles_4_4_4_2_a
import org.codice.compliance.utils.NodeWrapper
import org.codice.compliance.verification.profile.SingleLogoutProfileVerifier

class SingleLogoutProfileVerifierSpec : StringSpec() {
    private val correctIdpIssuer = "http://correct.idp.issuer"
    private val incorrectIdpIssuer = "incorrect/idp/issuer"

    init {
        System.setProperty(IMPLEMENTATION_PATH,
                Resources.getResource("implementation").path)

        "logout request with correct issuer should pass" {
            NodeWrapper(Common.buildDom(createLogoutRequest(correctIdpIssuer))).let {
                SingleLogoutProfileVerifier(it).verify()
            }
        }

        "logout request with incorrect issuer should fail" {
            NodeWrapper(Common.buildDom(createLogoutRequest(incorrectIdpIssuer))).let {
                shouldThrow<SAMLComplianceException> {
                    SingleLogoutProfileVerifier(it).verify()
                }.message?.shouldContain(SAMLProfiles_4_4_4_1_a.message)
            }
        }

        "logout response with correct issuer should pass" {
            NodeWrapper(Common.buildDom(createLogoutResponse(correctIdpIssuer))).let {
                SingleLogoutProfileVerifier(it).verify()
            }
        }

        "logout response with incorrect issuer should fail" {
            NodeWrapper(Common.buildDom(createLogoutResponse(incorrectIdpIssuer))).let {
                shouldThrow<SAMLComplianceException> {
                    SingleLogoutProfileVerifier(it).verify()
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

    private fun createLogoutRequest(issuer: String): String {
        return """
            |<s:LogoutRequest
            |xmlns:s="urn:oasis:names:tc:SAML:2.0:protocol"
            |xmlns:s2="urn:oasis:names:tc:SAML:2.0:assertion">
            |  <s2:Issuer>$issuer</s2:Issuer>
            |  <s2:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">
            |    admin
            |  </s2:NameID>
            |</s:LogoutRequest>
           """.trimMargin()
    }
}
