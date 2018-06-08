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

import com.jayway.restassured.response.Response
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_4_1_2_a
import org.codice.compliance.SAMLProfiles_4_1_4_2_a
import org.codice.compliance.SAMLProfiles_4_1_4_2_b
import org.codice.compliance.SAMLProfiles_4_1_4_2_c
import org.codice.compliance.SAMLProfiles_4_1_4_2_d
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.utils.ASSERTION
import org.codice.compliance.utils.ENTITY
import org.codice.compliance.utils.FORMAT
import org.codice.compliance.utils.RESPONSE
import org.codice.compliance.utils.TestCommon.Companion.idpMetadata
import org.codice.compliance.utils.determineBinding
import org.codice.compliance.verification.core.EncryptionVerifier.Companion.hasEncryptionAssertions
import org.codice.compliance.verification.core.SubjectComparisonVerifier
import org.codice.compliance.verification.profile.subject.confirmations.BearerSubjectConfirmationVerification
import org.codice.compliance.verification.profile.subject.confirmations.HolderOfKeySubjectConfirmationVerification
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT
import org.w3c.dom.Node

class SingleSignOnProfileVerifier(private val samlResponseDom: Node) {

    /** 4.1.4.2 <Response> Usage */
    fun verify() {
        if (samlResponseDom.children(SIGNATURE).isNotEmpty() || hasEncryptionAssertions == true)
            verifyIssuer(samlResponseDom)

        verifySSOAssertions()
        SubjectComparisonVerifier(samlResponseDom).verifySubjectsMatchSSO()
        BearerSubjectConfirmationVerification(samlResponseDom).verify()
        HolderOfKeySubjectConfirmationVerification(samlResponseDom).verify()
    }

    /** 4.1.2 Profile Overview */
    fun verifyBinding(httpResponse: Response) {
        if (httpResponse.determineBinding() == HTTP_REDIRECT) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_2_a,
                    message = "The <Response> cannot be sent using Redirect Binding.")
        }
    }

    /** 4.1.4.2 <Response> Usage */
    private fun verifyIssuer(node: Node) {
        require(node.localName == RESPONSE || node.localName == ASSERTION)
        val issuers = node.children("Issuer")

        if (issuers.size != 1)
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_a,
                message = "${issuers.size} Issuer elements were found under ${node.localName}.",
                node = node)

        val issuer = issuers.first()
        if (issuer.textContent != idpMetadata.entityId)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_4_1_4_2_b,
                property = "${node.localName}'s issuer",
                expected = idpMetadata.entityId,
                actual = issuer.textContent,
                node = node)

        val issuerFormat = issuer.attributeText(FORMAT)
        if (issuerFormat != null &&
            issuerFormat != ENTITY)
            throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_4_1_4_2_c,
                property = FORMAT,
                actual = issuerFormat,
                expected = ENTITY,
                node = node)
    }

    /** 4.1.4.2 <Response> Usage */
    private fun verifySSOAssertions() {
        val assertions = samlResponseDom.children(ASSERTION)
        if (assertions.isEmpty()) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_d,
                    message = "No Assertions found.",
                    node = samlResponseDom)
        }
        assertions.forEach { verifyIssuer(it) }
    }
}
