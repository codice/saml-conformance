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
package org.codice.compliance.verification.profile

import io.restassured.response.Response
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_4_1_2_a
import org.codice.compliance.SAMLProfiles_4_1_4_2_a
import org.codice.compliance.SAMLProfiles_4_1_4_2_b
import org.codice.compliance.SAMLProfiles_4_1_4_2_c
import org.codice.compliance.children
import org.codice.compliance.utils.ASSERTION
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.utils.determineBinding
import org.codice.compliance.verification.core.SubjectComparisonVerifier
import org.codice.compliance.verification.profile.ProfilesVerifier.Companion.verifyIssuer
import org.codice.compliance.verification.profile.subject.confirmations.BearerSubjectConfirmationVerifier
import org.codice.compliance.verification.profile.subject.confirmations.HolderOfKeySubjectConfirmationVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT

class SingleSignOnProfileVerifier(private val response: NodeDecorator) {

    /** 4.1.4.2 <Response> Usage */
    fun verify() {
        if (response.isSigned || response.hasEncryptedAssertion)
            verifyIssuer(response, SAMLProfiles_4_1_4_2_a)

        verifySSOAssertions()
        SubjectComparisonVerifier(response).verifySubjectsMatchSSO()
        BearerSubjectConfirmationVerifier(response).verify()
        HolderOfKeySubjectConfirmationVerifier(response).verify()
    }

    /** 4.1.2 Profile Overview */
    fun verifyBinding(httpResponse: Response) {
        if (httpResponse.determineBinding() == HTTP_REDIRECT) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_2_a,
                    message = "The <Response> cannot be sent using Redirect Binding.")
        }
    }

    /** 4.1.4.2 <Response> Usage */
    private fun verifySSOAssertions() {
        val assertions = response.children(ASSERTION)
        if (assertions.isEmpty()) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_b,
                    message = "No Assertions found.",
                    node = response)
        }
        assertions.forEach { verifyIssuer(it, SAMLProfiles_4_1_4_2_c) }
    }
}
