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
import org.codice.compliance.SAMLProfiles_4_1_4_2_g
import org.codice.compliance.SAMLProfiles_4_1_4_2_h
import org.codice.compliance.SAMLProfiles_4_1_4_2_i
import org.codice.compliance.SAMLProfiles_4_1_4_2_j
import org.codice.compliance.SAMLProfiles_4_1_4_2_k
import org.codice.compliance.attributeNode
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon.Companion.ASSERTION
import org.codice.compliance.utils.TestCommon.Companion.AUDIENCE
import org.codice.compliance.utils.TestCommon.Companion.AUTHN_STATEMENT
import org.codice.compliance.utils.TestCommon.Companion.BEARER
import org.codice.compliance.utils.TestCommon.Companion.ENTITY
import org.codice.compliance.utils.TestCommon.Companion.FORMAT
import org.codice.compliance.utils.TestCommon.Companion.REQUEST_ID
import org.codice.compliance.utils.TestCommon.Companion.SP_ISSUER
import org.codice.compliance.utils.TestCommon.Companion.SUBJECT
import org.codice.compliance.utils.TestCommon.Companion.SUBJECT_CONFIRMATION
import org.codice.compliance.utils.TestCommon.Companion.idpMetadata
import org.codice.compliance.utils.determineBinding
import org.codice.security.saml.SamlProtocol
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorImpl
import org.w3c.dom.Node

class SingleSignOnProfileVerifier(private val response: Node,
                                  private val acsUrl: String?) {
    companion object {
        fun verifyBinding(response: Response) {
            if (response.determineBinding() == SamlProtocol.Binding.HTTP_REDIRECT) {
                throw SAMLComplianceException.create(SAMLProfiles_4_1_2_a,
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
                        response.children(ASSERTION)
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

            val issuerFormat = issuer.attributeText(FORMAT)
            if (issuerFormat != null &&
                    issuerFormat != ENTITY)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_4_1_4_2_c,
                        property = FORMAT,
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
        val assertions = response.children(ASSERTION)
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
                        .filter { it.children(SUBJECT_CONFIRMATION).isNotEmpty() }
                        .flatMap { it.children(SUBJECT_CONFIRMATION) }
                        .filter { it.attributeText("Method") == BEARER }
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
                            it.attributeText("Recipient") == acsUrl &&
                                    it.attributeNode("NotOnOrAfter") != null &&
                                    it.attributeNode("NotBefore") == null &&
                                    it.attributeText("InResponseTo") == REQUEST_ID
                        }) {
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
                        .any { it.attributeNode("SessionIndex") == null })
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
                        .filter { it.children(AUDIENCE).isNotEmpty() }
                        .flatMap { it.children(AUDIENCE) }
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
