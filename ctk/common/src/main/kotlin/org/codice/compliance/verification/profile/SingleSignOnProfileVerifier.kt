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
import org.codice.compliance.utils.ASSERTION
import org.codice.compliance.utils.AUDIENCE
import org.codice.compliance.utils.AUTHN_STATEMENT
import org.codice.compliance.utils.BEARER
import org.codice.compliance.utils.ENTITY
import org.codice.compliance.utils.FORMAT
import org.codice.compliance.utils.SUBJECT
import org.codice.compliance.utils.SUBJECT_CONFIRMATION
import org.codice.compliance.utils.TestCommon.Companion.REQUEST_ID
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.compliance.utils.TestCommon.Companion.getServiceUrl
import org.codice.compliance.utils.TestCommon.Companion.idpMetadata
import org.codice.compliance.utils.determineBinding
import org.codice.compliance.verification.core.SubjectComparisonVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorImpl
import org.w3c.dom.Node

class SingleSignOnProfileVerifier(private val authnRequest: AuthnRequest,
                                  private val samlResponseDom: Node) {
    /**
     * Verify response against the Core Spec document
     * 4.1.4.2 <Response> Usage
     */
    fun verify() {
        verifyIssuer()
        verifySsoAssertions()
        SubjectComparisonVerifier(samlResponseDom).verifySubjectsMatchSSO()
        ProfilesVerifier(samlResponseDom).verify()
    }

    fun verifyBinding(httpResponse: Response) {
        if (httpResponse.determineBinding() == HTTP_REDIRECT) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_2_a,
                    message = "The <Response> cannot be sent using Redirect Binding.")
        }
    }

    /**
     * Checks the issuer element against the SSO profile spec
     * 4.1.4.2 <Response> Usage
     */
    private fun verifyIssuer() {
        if (samlResponseDom.localName == "Response" &&
                (samlResponseDom.children(SIGNATURE).isNotEmpty() ||
                        samlResponseDom.children(ASSERTION)
                                .any {
                                    it.children(SIGNATURE).isNotEmpty()
                                })) {
            val issuers = samlResponseDom.children("Issuer")

            if (issuers.size != 1)
                throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_a,
                        message = "${issuers.size} Issuer elements were found.",
                        node = samlResponseDom)

            val issuer = issuers[0]
            if (issuer.textContent !=
                    (idpMetadata.descriptor?.parent as EntityDescriptorImpl).entityID)
                throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_b,
                        message = "Issuer value of ${issuer.textContent} does not match the " +
                                "issuing IdP.",
                        node = samlResponseDom)

            val issuerFormat = issuer.attributeText(FORMAT)
            if (issuerFormat != null &&
                    issuerFormat != ENTITY)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_4_1_4_2_c,
                        property = FORMAT,
                        actual = issuerFormat,
                        expected = ENTITY,
                        node = samlResponseDom)
        }
    }

    /**
     * Verify Assertion Elements against the profile document
     * 4.1.4.2 <Response> Usage
     */
    private fun verifySsoAssertions() {
        val assertions = samlResponseDom.children(ASSERTION)
        val encryptedAssertions = samlResponseDom.children("EncryptedAssertion")

        if (assertions.isEmpty() && encryptedAssertions.isEmpty()) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_d,
                    message = "No Assertions found.",
                    node = samlResponseDom)
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
                    node = samlResponseDom)

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
                            it.attributeText("Recipient") ==
                                getServiceUrl(HTTP_POST, samlResponseDom) &&
                                    it.attributeNode("NotOnOrAfter") != null &&
                                    it.attributeNode("NotBefore") == null &&
                                    it.attributeText("InResponseTo") == REQUEST_ID
                        }) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_h,
                    message = "There were no bearer SubjectConfirmation elements that matched " +
                            "the criteria below.",
                    node = samlResponseDom)
        }
    }

    private fun verifyAssertionsHaveAuthnStmts(bearerAssertions: List<Node>) {
        if (bearerAssertions.all { it.children(AUTHN_STATEMENT).isEmpty() })
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_i,
                    message = "A Bearer Assertion with an AuthnStatement was not found.",
                    node = samlResponseDom)
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
                    node = samlResponseDom)
    }

    private fun verifyBearerAssertionsContainAudienceRestriction(bearerAssertions: List<Node>) {
        if (bearerAssertions
                        .filter { it.children("Conditions").isNotEmpty() }
                        .flatMap { it.children("Conditions") }
                        .map { extractAudienceRestriction(it) }
                        .filter { it.children(AUDIENCE).isNotEmpty() }
                        .flatMap { it.children(AUDIENCE) }
                        .none { it.textContent == currentSPIssuer }) {

            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_k,
                    message = "An <Audience> containing the service provider's issuer was " +
                            "not found",
                    node = samlResponseDom)
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
