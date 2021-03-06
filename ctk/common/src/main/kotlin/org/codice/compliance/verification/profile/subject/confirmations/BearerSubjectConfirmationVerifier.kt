/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.profile.subject.confirmations

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_4_1_4_2_e
import org.codice.compliance.SAMLProfiles_4_1_4_2_f
import org.codice.compliance.SAMLProfiles_4_1_4_2_g
import org.codice.compliance.SAMLProfiles_4_1_4_2_h
import org.codice.compliance.SAMLProfiles_4_1_4_2_i
import org.codice.compliance.attributeNode
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.utils.ASSERTION
import org.codice.compliance.utils.AUDIENCE
import org.codice.compliance.utils.AUTHN_STATEMENT
import org.codice.compliance.utils.BEARER
import org.codice.compliance.utils.SESSION_INDEX
import org.codice.compliance.utils.SUBJECT
import org.codice.compliance.utils.SUBJECT_CONFIRMATION
import org.codice.compliance.utils.SUBJECT_CONFIRMATION_DATA
import org.codice.compliance.utils.TestCommon
import org.codice.compliance.utils.TestCommon.Companion.REQUEST_ID
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.compliance.utils.TestCommon.Companion.idpMetadata
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.w3c.dom.Node

class BearerSubjectConfirmationVerifier(private val samlResponseDom: Node) {

    private val bearerSubjectConfirmationPredicate = { node: Node ->
        node.attributeText("Recipient") ==
                TestCommon.getServiceUrl(HTTP_POST, samlResponseDom) &&
                node.attributeNode("NotOnOrAfter") != null &&
                node.attributeNode("NotBefore") == null &&
                node.attributeText("InResponseTo") == REQUEST_ID
    }

    fun verify() {
        val bearerAssertions = verifyBearerSubjectConfirmations()
        verifyAuthnStatements(bearerAssertions)
        verifyAudienceRestriction(bearerAssertions)
    }

    @Suppress("ComplexCondition")
    private fun verifyBearerSubjectConfirmations(): List<Node> {
        val (bearerSubjectConfirmations, bearerAssertions) =
                samlResponseDom.children(ASSERTION)
                        .filter { it.children(SUBJECT).isNotEmpty() }
                        .flatMap { it.children(SUBJECT) }
                        .filter { it.children(SUBJECT_CONFIRMATION).isNotEmpty() }
                        .flatMap { it.children(SUBJECT_CONFIRMATION) }
                        .filter { it.attributeText("Method") == BEARER }
                        .map { it to it.parentNode.parentNode }
                        .unzip()

        if (bearerAssertions.isEmpty())
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_e,
                    message = "No bearer SubjectConfirmation elements were found.",
                    node = samlResponseDom)

        if (bearerSubjectConfirmations
                        .filter { it.children(SUBJECT_CONFIRMATION_DATA).isNotEmpty() }
                        .flatMap { it.children(SUBJECT_CONFIRMATION_DATA) }
                        .none { bearerSubjectConfirmationPredicate(it) }) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_f,
                    message = "There were no bearer SubjectConfirmation elements that matched " +
                            "the criteria below.",
                    node = samlResponseDom)
        }
        return bearerAssertions
    }

    private fun verifyAuthnStatements(bearerAssertions: List<Node>) {
        if (bearerAssertions.all { it.children(AUTHN_STATEMENT).isEmpty() })
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_g,
                    message = "A Bearer Assertion with an AuthnStatement was not found.",
                    node = samlResponseDom)

        if (idpMetadata.descriptor?.singleLogoutServices?.isEmpty() == true) return

        if (bearerAssertions
                        .flatMap { it.children(AUTHN_STATEMENT) }
                        .any { it.attributeNode(SESSION_INDEX) == null })
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_h,
                    message = "Single Logout support found in IdP metadata, but no " +
                            "SessionIndex was found for AuthnStatement.",
                    node = samlResponseDom)
    }

    private fun verifyAudienceRestriction(bearerAssertions: List<Node>) {
        val audienceRestrictions = bearerAssertions
                .flatMap { it.children("Conditions") }
                .map { extractAudienceRestriction(it) }

        audienceRestrictions.forEach {
            if (it.children(AUDIENCE)
                            .none { it.textContent == currentSPIssuer }) {

                throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_i,
                        message = "An <Audience> with $currentSPIssuer was found",
                        node = it)
            }
        }
    }

    private fun extractAudienceRestriction(condition: Node): Node {
        val audienceRestriction = condition.children("AudienceRestriction")
        if (audienceRestriction.size != 1) {
            throw SAMLComplianceException.createWithPropertyMessage(SAMLProfiles_4_1_4_2_i,
                    property = "AudienceRestriction",
                    actual = audienceRestriction.toString(),
                    expected = "One <AudienceRestriction>",
                    node = condition)
        }
        return audienceRestriction.first()
    }
}
