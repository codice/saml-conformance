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

import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLSpecRefMessage.SAMLProfiles_4_1_4_2_a
import org.codice.compliance.SAMLSpecRefMessage.SAMLProfiles_4_1_4_2_b
import org.codice.compliance.SAMLSpecRefMessage.SAMLProfiles_4_1_4_2_c
import org.codice.compliance.SAMLSpecRefMessage.SAMLProfiles_4_1_4_2_d
import org.codice.compliance.SAMLSpecRefMessage.SAMLProfiles_4_1_4_2_f
import org.codice.compliance.SAMLSpecRefMessage.SAMLProfiles_4_1_4_2_g
import org.codice.compliance.SAMLSpecRefMessage.SAMLProfiles_4_1_4_2_h
import org.codice.compliance.SAMLSpecRefMessage.SAMLProfiles_4_1_4_2_i
import org.codice.compliance.SAMLSpecRefMessage.SAMLProfiles_4_1_4_2_j
import org.codice.compliance.SAMLSpecRefMessage.SAMLProfiles_4_1_4_2_k
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon.Companion.ID
import org.codice.compliance.utils.TestCommon.Companion.SP_ISSUER
import org.codice.compliance.utils.TestCommon.Companion.idpMetadata
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorImpl
import org.w3c.dom.Node

class SingleSignOnProfileVerifier(private val response: Node, private val acsUrl: String?) {
    /**
     * Verify response against the Core Spec document
     * 4.1.4.2 <Response> Usage
     */
    fun verify() {
        verifyIssuer()
        verifySsoAssertions()
        ProfilesVerifier(response).verify()
    }

    /**
     * Checks the issuer element against the SSO profile spec
     * 4.1.4.2 <Response> Usage
     *
     * @param node - Node containing the issuer to verify.
     */
    private fun verifyIssuer() {
        if (response.localName == "Response" &&
                (response.children(SIGNATURE).isNotEmpty() ||
                        response.children("Assertion").any { it.children(SIGNATURE).isNotEmpty() })) {
            val issuers = response.children("Issuer")

            if (issuers.size != 1)
                throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_a,
                        message = "${issuers.size} Issuer elements were found.",
                        node = response)

            val issuer = issuers[0]
            if (issuer.textContent != (idpMetadata.descriptor?.parent as EntityDescriptorImpl).entityID)
                throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_b,
                        message = "Issuer value of ${issuer.textContent} does not match the issuing IdP.",
                        node = response)

            val issuerFormat = issuer.attributes.getNamedItem("Format")?.textContent
            if (issuerFormat != null && issuerFormat != "urn:oasis:names:tc:SAML:2.0:nameid-format:entity")
                throw SAMLComplianceException.createWithPropertyMessage(code = SAMLProfiles_4_1_4_2_c,
                        property = "Format",
                        actual = issuerFormat,
                        expected = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
                        node = response)
        }
    }

    /**
     * Verify Assertion Elements against the profile document
     * 4.1.4.2 <Response> Usage
     */
    private fun verifySsoAssertions() {
        val assertions = response.children("Assertion")
        if (assertions.isEmpty()) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_d, message = "No Assertions found.", node = response)
        }

        assertions.forEach {
            verifyIssuer()
            verifyHasSubject(it)
            verifyBearerSubjectConfirmations(it)

            //todo - We can't throw an exception here because the spec says there could be assertions without bearer
            verifyAssertionsHaveAuthnStmts(it)
            verifySingleLogoutIncludesSessionIndex(it)

            // Assuming the AudienceRestriction is under Conditions
            verifyBearerAssertionsContainAudienceRestriction(it)
        }
    }

    private fun verifyBearerAssertionsContainAudienceRestriction(assertion: Node) {
        if (assertion.children("Conditions").isNotEmpty()) {
            val audience = assertion.children("Conditions")
                    .firstOrNull()
                    ?.children("AudienceRestriction")
                    ?.firstOrNull()
                    ?.children("Audience")
                    ?.firstOrNull()
                    ?.textContent

            if (audience != SP_ISSUER)
                throw SAMLComplianceException.createWithPropertyMessage(code = SAMLProfiles_4_1_4_2_k,
                        property = "Audience",
                        actual = audience,
                        expected = SP_ISSUER,
                        node = response)
        }
    }

    private fun verifySingleLogoutIncludesSessionIndex(assertion: Node) {
        if (idpMetadata.descriptor == null) return

        if (idpMetadata.descriptor?.singleLogoutServices?.isNotEmpty() == true) return

        assertion.children("AuthnStatement").forEach {
            if (it.attributes.getNamedItem("SessionIndex") == null) {
                throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_j,
                        message = "Single Logout support found in IdP metadata, but no SessionIndex was" +
                                " found.",
                        node = response)
            }
        }
    }

    private fun verifyAssertionsHaveAuthnStmts(assertion: Node) {
        if (assertion.children("AuthnStatement").isEmpty()) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_i,
                    message = "A bearer Assertion was found without an AuthnStatement.",
                    node = response)
        }
    }

    @Suppress("ComplexCondition")
    private fun verifyBearerSubjectConfirmations(assertion: Node) {
        val bearerSubjectConfirmations = assertion.children("Subject")[0].children("SubjectConfirmation")
                .filter {
                    it.attributes.getNamedItem("Method").textContent ==
                            "urn:oasis:names:tc:SAML:2.0:cm:bearer"
                }.toList()

        //todo - We can't throw an exception here because the spec says there could be assertions without bearer
        // SubjectConfirmation
        if (bearerSubjectConfirmations.isEmpty())
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_g,
                    message = "No bearer SubjectConfirmation elements were found.",
                    node = response)

        // Check if there is one SubjectConfirmationData with a Recipient, InResponseTo and NotOnOrAfter
        if (bearerSubjectConfirmations
                        .filter { it.children("SubjectConfirmationData").isNotEmpty() }
                        .flatMap { it.children("SubjectConfirmationData") }
                        .none {
                            it.attributes.getNamedItem("Recipient").textContent == acsUrl &&
                                    it.attributes.getNamedItem("InResponseTo").textContent == ID &&
                                    it.attributes.getNamedItem("NotOnOrAfter") != null &&
                                    it.attributes.getNamedItem("NotBefore") == null
                        }) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_h,
                    message = "There were no bearer SubjectConfirmation elements that matched the criteria below.",
                    node = response)
        }
    }

    private fun verifyHasSubject(assertion: Node) {
        if (assertion.children("Subject").size != 1) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_f,
                    message = "${assertion.children("Subject").size} Subject elements were found.",
                    node = response)
        }
    }
}
