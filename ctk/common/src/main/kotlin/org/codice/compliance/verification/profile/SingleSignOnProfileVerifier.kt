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
import org.codice.compliance.SAMLProfiles_4_1_2
import org.codice.compliance.SAMLProfiles_4_1_4_2_a
import org.codice.compliance.SAMLProfiles_4_1_4_2_b
import org.codice.compliance.SAMLProfiles_4_1_4_2_c
import org.codice.compliance.SAMLProfiles_4_1_4_2_d
import org.codice.compliance.SAMLProfiles_4_1_4_2_g
import org.codice.compliance.SAMLProfiles_4_1_4_2_h
import org.codice.compliance.SAMLProfiles_4_1_4_2_i
import org.codice.compliance.SAMLProfiles_4_1_4_2_j
import org.codice.compliance.SAMLProfiles_4_1_4_2_k
import org.codice.compliance.children
import org.codice.compliance.saml.plugin.IdpRedirectResponse
import org.codice.compliance.utils.TestCommon.Companion.BEARER
import org.codice.compliance.utils.TestCommon.Companion.ENTITY
import org.codice.compliance.utils.TestCommon.Companion.ID
import org.codice.compliance.utils.TestCommon.Companion.SP_ISSUER
import org.codice.compliance.utils.TestCommon.Companion.idpMetadata
import org.codice.compliance.utils.decorators.IdpResponseDecorator
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorImpl
import org.w3c.dom.Node

class SingleSignOnProfileVerifier(private val response: Node,
                                  private val acsUrl: String?) {
    companion object {
        private const val SUBJECT = "Subject"
        private const val AUTHN_STATEMENT = "AuthnStatement"
        fun verifyBinding(response: IdpResponseDecorator) {
            if (response is IdpRedirectResponse) {
                throw SAMLComplianceException.create(SAMLProfiles_4_1_2,
                        message = "The <Response> cannot be sent using Redirect Binding.")
            }
        }
    }

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
     */
    private fun verifyIssuer() {
        if (response.localName == "Response" &&
                (response.children(SIGNATURE).isNotEmpty() ||
                        response.children("Assertion")
                                .any {
                                    it.children(SIGNATURE).isNotEmpty()
                                })) {
            val issuers = response.children("Issuer")

            if (issuers.size != 1)
                throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_a,
                        message = "${issuers.size} Issuer elements were found.",
                        node = response)

            val issuer = issuers[0]
            if (issuer.textContent !=
                    (idpMetadata.descriptor?.parent as EntityDescriptorImpl).entityID)
                throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_b,
                        message = "Issuer value of ${issuer.textContent} does not match the " +
                                "issuing IdP.",
                        node = response)

            val issuerFormat = issuer.attributes.getNamedItem("Format")?.textContent
            if (issuerFormat != null &&
                    issuerFormat != ENTITY)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_4_1_4_2_c,
                        property = "Format",
                        actual = issuerFormat,
                        expected = ENTITY,
                        node = response)
        }
    }

    /**
     * Verify Assertion Elements against the profile document
     * 4.1.4.2 <Response> Usage
     */
    private fun verifySsoAssertions() {
        val assertions = response.children("Assertion")
        val encryptedAssertions = response.children("EncryptedAssertion")

        if (assertions.isEmpty() && encryptedAssertions.isEmpty()) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_d,
                    message = "No Assertions found.",
                    node = response)
        }

        assertions.forEach { verifyIssuer() }

        val (bearerSubjectConfirmations, bearerAssertions) =
                assertions.filter { it.children(SUBJECT).isNotEmpty() }
                        .flatMap { it.children(SUBJECT) }
                        .filter { it.children("SubjectConfirmation").isNotEmpty() }
                        .flatMap { it.children("SubjectConfirmation") }
                        .filter { it.attributes.getNamedItem("Method").textContent == BEARER }
                        .map { it to it.parentNode.parentNode }
                        .unzip()

        if (bearerAssertions.isEmpty())
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_g,
                    message = "No bearer SubjectConfirmation elements were found.",
                    node = response)

        verifyBearerSubjectConfirmations(bearerSubjectConfirmations)
        verifyAssertionsHaveAuthnStmts(bearerAssertions)
        verifySingleLogoutIncludesSessionIndex(bearerAssertions)
        verifyBearerAssertionsContainAudienceRestriction(bearerAssertions)
    }

    @Suppress("ComplexCondition")
    private fun verifyBearerSubjectConfirmations(bearerSubjectConfirmations: List<Node>) {
        if (bearerSubjectConfirmations
                        .filter { it.children("SubjectConfirmationData").isNotEmpty() }
                        .flatMap { it.children("SubjectConfirmationData") }
                        .none {
                            it.attributes.getNamedItem("Recipient").textContent == acsUrl &&
                                    it.attributes.getNamedItem("NotOnOrAfter") != null &&
                                    it.attributes.getNamedItem("NotBefore") == null &&
                                    it.attributes.getNamedItem("InResponseTo").textContent ==
                                    ID }) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_h,
                    message = "There were no bearer SubjectConfirmation elements that matched " +
                            "the criteria below.",
                    node = response)
        }
    }

    private fun verifyAssertionsHaveAuthnStmts(bearerAssertions: List<Node>) {
        if (bearerAssertions.all { it.children(AUTHN_STATEMENT).isEmpty() })
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_i,
                    message = "A Bearer Assertion with an AuthnStatement was not found.",
                    node = response)
    }

    private fun verifySingleLogoutIncludesSessionIndex(bearerAssertions: List<Node>) {
        if (idpMetadata.descriptor == null) return

        if (idpMetadata.descriptor?.singleLogoutServices?.isNotEmpty() == true) return

        if (bearerAssertions.filter { it.children(AUTHN_STATEMENT).isNotEmpty() }
                        .flatMap { it.children(AUTHN_STATEMENT) }
                        .any { it.attributes.getNamedItem("SessionIndex") == null })
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_j,
                    message = "Single Logout support found in IdP metadata, but no " +
                            "SessionIndex was found.",
                    node = response)
    }

    private fun verifyBearerAssertionsContainAudienceRestriction(bearerAssertions: List<Node>) {
        if (bearerAssertions
                        .filter { it.children("Conditions").isNotEmpty() }
                        .flatMap { it.children("Conditions") }
                        .map { extractAudienceRestriction(it) }
                        .filter { it.children("Audience").isNotEmpty() }
                        .flatMap { it.children("Audience") }
                        .none { it.textContent == SP_ISSUER }) {

            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_k,
                    message = "An <Audience> containing the service provider's issuer was " +
                            "not found",
                    node = response)
        }
    }

    private fun extractAudienceRestriction(condition: Node): Node {
        val audienceRestriction = condition.children("AudienceRestriction")
        if (audienceRestriction.size != 1) {
            throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_4_1_4_2_k,
                    property = "AudienceRestriction",
                    actual = audienceRestriction.toString(),
                    expected = "One <AudienceRestriction>",
                    node = condition)
        }
        return audienceRestriction.first()
    }
}
