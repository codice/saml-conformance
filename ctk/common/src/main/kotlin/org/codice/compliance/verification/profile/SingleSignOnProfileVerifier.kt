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
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_3_1_a
import org.codice.compliance.SAMLProfiles_3_1_b
import org.codice.compliance.SAMLProfiles_3_1_c
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
import org.codice.compliance.attributeNodeNS
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.ASSERTION
import org.codice.compliance.utils.ASSERTION_NAMESPACE
import org.codice.compliance.utils.AUDIENCE
import org.codice.compliance.utils.AUTHN_STATEMENT
import org.codice.compliance.utils.BEARER
import org.codice.compliance.utils.ENTITY
import org.codice.compliance.utils.FORMAT
import org.codice.compliance.utils.HOLDER_OF_KEY_URI
import org.codice.compliance.utils.KEY_INFO_CONFIRMATION_DATA_TYPE
import org.codice.compliance.utils.SUBJECT
import org.codice.compliance.utils.SUBJECT_CONFIRMATION
import org.codice.compliance.utils.SUBJECT_CONFIRMATION_DATA
import org.codice.compliance.utils.TestCommon.Companion.REQUEST_ID
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.compliance.utils.TestCommon.Companion.getServiceUrl
import org.codice.compliance.utils.TestCommon.Companion.idpMetadata
import org.codice.compliance.utils.XSI
import org.codice.compliance.utils.determineBinding
import org.codice.compliance.verification.core.SubjectComparisonVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.codice.security.saml.SamlProtocol.Binding.HTTP_REDIRECT
import org.opensaml.saml.saml2.metadata.impl.EntityDescriptorImpl
import org.w3c.dom.Node

@Suppress("TooManyFunctions")
class SingleSignOnProfileVerifier(private val samlResponseDom: Node) {
    /**
     * Verify response against the Core Spec document
     * 4.1.4.2 <Response> Usage
     */
    fun verify() {
        if (samlResponseDom.children(SIGNATURE).isNotEmpty())
            verifyIssuer(samlResponseDom)
        verifySsoAssertions()
        verifyHolderOfKey()
        SubjectComparisonVerifier(samlResponseDom).verifySubjectsMatchSSO()
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
    private fun verifyIssuer(node: Node) {
        require(node.localName == "Response" || node.localName == ASSERTION)
        val issuers = node.children("Issuer")

        if (issuers.size != 1)
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_a,
                message = "${issuers.size} Issuer elements were found.",
                node = node)

        val issuer = issuers[0]
        if (issuer.textContent !=
            (idpMetadata.descriptor?.parent as EntityDescriptorImpl).entityID)
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_b,
                message = "Issuer value of ${issuer.textContent} does not match the " +
                    "issuing IdP.",
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

        assertions.forEach { verifyIssuer(it) }

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
                        .filter { it.children(SUBJECT_CONFIRMATION_DATA).isNotEmpty() }
                        .flatMap { it.children(SUBJECT_CONFIRMATION_DATA) }
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

    /**
     * 3.1 Holder of Key
     */
    internal fun verifyHolderOfKey() {
        val holderOfKeyList = samlResponseDom.recursiveChildren(SUBJECT_CONFIRMATION)
            .filter { it.attributeText("Method") == HOLDER_OF_KEY_URI }

        if (holderOfKeyList.isEmpty()) return

        holderOfKeyList.forEach {
            val subjectConfirmationDataElements = it.children(SUBJECT_CONFIRMATION_DATA)

            if (subjectConfirmationDataElements.isEmpty())
                throw SAMLComplianceException.create(SAMLProfiles_3_1_a,
                    message = "<SubjectConfirmationData> not found within Holder of Key " +
                        "<SubjectConfirmation>",
                    node = samlResponseDom)

            subjectConfirmationDataElements.forEach { verifyHolderOfKeyData(it) }
        }
    }

    private fun verifyHolderOfKeyData(node: Node) {
        val type = node.attributeNodeNS(XSI, "type")
        if (type != null) {
            if (!type.textContent.contains(":"))
                throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_3_1_b,
                    property = "type",
                    actual = type.textContent,
                    expected = KEY_INFO_CONFIRMATION_DATA_TYPE,
                    node = node)

            val (namespace, value) = type.textContent.split(":")
            if (value != KEY_INFO_CONFIRMATION_DATA_TYPE)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_3_1_b,
                    property = "type",
                    actual = value,
                    expected = KEY_INFO_CONFIRMATION_DATA_TYPE,
                    node = node)

            // SSO Response must have at least one assertion with an assertion namespace
            val assertionNameSpacePrefix = samlResponseDom.children(ASSERTION)
                .first()
                .nodeName.split(":")
                .first()
            if (namespace != assertionNameSpacePrefix)
                throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_3_1_b,
                    property = "namespace prefix",
                    actual = namespace,
                    expected = "$assertionNameSpacePrefix which maps to " +
                        ASSERTION_NAMESPACE,
                    node = node)
        }

        val keyInfos = node.children("KeyInfo")
        if (keyInfos.isEmpty())
            throw SAMLComplianceException.create(SAMLProfiles_3_1_a,
                message = "<ds:KeyInfo> not found within the <SubjectConfirmationData> " +
                    "element.",
                node = node)

        keyInfos.forEach {
            if (it.children("KeyValue").size > 1)
                throw SAMLComplianceException.create(SAMLProfiles_3_1_c,
                    message = "<ds:KeyInfo> must not have multiple values.",
                    node = node)
        }
    }
}
