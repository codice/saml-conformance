package org.codice.compliance.profiles

import org.codice.compliance.*
import org.w3c.dom.Node

fun verifySsoAssertions(response: Node) {
    val assertions = response.children("Assertion")
    // todo - If the identity provider wishes to return an error, it MUST NOT include any assertions in the <Response> message.
    if (assertions.isEmpty()) throw SAMLComplianceException.create("1")

    for (assertion in assertions) {
        verifyIssuer(assertion)

        val subjects = assertion.children("Subject")
        val conditions = assertion.children("Conditions")
        val authnStatements = assertion.children("AuthnStatement")

        // todo - If multiple assertions are included, then each assertion's <Subject> element MUST refer to the
        // same principal. It is allowable for the content of the <Subject> elements to differ (e.g. using different
        // <NameID> or alternative <SubjectConfirmation> elements).

        if (subjects.isEmpty() || subjects.size > 1) throw SAMLComplianceException.create("2")
        val subject = subjects[0]

        val bearerSubjectConfirmations = mutableListOf<Node>()
        subject.children("SubjectConfirmation")
                .filter { it.attributes.getNamedItem("Method").textContent == "urn:oasis:names:tc:SAML:2.0:cm:bearer" }
                .toCollection(bearerSubjectConfirmations)
        if (bearerSubjectConfirmations.isEmpty())
            throw SAMLComplianceException.create("3")

        // Check if NotBefore is an attribute (it shouldn't)
        val dataWithNotBefore = bearerSubjectConfirmations
                .filter { it.children("SubjectConfirmationData").isNotEmpty() }
                .flatMap { it -> it.children("SubjectConfirmationData") }
                .filter { it.attributes.getNamedItem("NotBefore") != null }
                .count()

        // Check if there is one SubjectConfirmationData with a Recipient, InResponseTo and NotOnOrAfter
        val bearerSubjectConfirmationsData = mutableListOf<Node>()
        bearerSubjectConfirmations
                .filter { it.children("SubjectConfirmationData").isNotEmpty() }
                .flatMap { it -> it.children("SubjectConfirmationData") }
                .filter { it.attributes.getNamedItem("Recipient").textContent == ACS }
                .filter { it.attributes.getNamedItem("InResponseTo").textContent == ID }
                .filter { it.attributes.getNamedItem("NotOnOrAfter") != null }
                .toCollection(bearerSubjectConfirmationsData)

        if (dataWithNotBefore > 0 && bearerSubjectConfirmationsData.isEmpty()) throw SAMLComplianceException.create("4")

        if (authnStatements.isEmpty()) throw SAMLComplianceException.create("5")

        // todo - [AuthnStatement] that reflects the authentication of the principal to the identity provider

        // todo - If the identity provider supports the Single Logout profile, defined in Section 4.4, any authentication statements MUST include a SessionIndex attribute to enable per-session logout requests by the service provider.

        if (idpParsedMetadata != null) {
            if (idpParsedMetadata.singleLogoutServices.isNotEmpty())
                authnStatements.forEach {
                    if (it.attributes.getNamedItem("SessionIndex") == null) throw SAMLComplianceException.create("7")
                }
        }

        // Assuming the AudienceRestriction is under Conditions
        if (conditions.isNotEmpty()) {
            val audienceRestriction = conditions
                    .firstOrNull()
                    ?.children("AudienceRestriction")
                    ?.firstOrNull()
                    ?: throw SAMLComplianceException.create("bearer.audiencerestriction")

            val audience = audienceRestriction.children("Audience").firstOrNull()
            if (audience == null || audience.textContent != SP_ISSUER) throw SAMLComplianceException.create("bearer.audiencerestriction")
        }
    }
}