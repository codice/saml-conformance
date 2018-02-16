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
package org.codice.compliance.assertions

import org.w3c.dom.Node

fun checkAssertions(assertions: List<Node>) {

    // todo - If the identity provider wishes to return an error, it MUST NOT include any assertions in the <Response> message.
    if (assertions.isEmpty()) throw SAMLComplianceException("[A Response] MUST contain at least one <Assertion>.")

    for (assertion in assertions) {

        // Get assertion Assertions.children
        val signitures = assertion.children("Signature")
        val subjects = assertion.children("Subject")
        val conditions = assertion.children("Conditions")
        val authnStatements = assertion.children("AuthnStatement")
        val attributeStatements = assertion.children("AttributeStatement")

        checkIssuer(assertion)

        // todo - If multiple assertions are included, then each assertion's <Subject> element MUST refer to the
        // same principal. It is allowable for the content of the <Subject> elements to differ (e.g. using different
        // <NameID> or alternative <SubjectConfirmation> elements).

        if (subjects.isEmpty() || subjects.size > 1) throw SAMLComplianceException("Any assertion issued for consumption using this profile MUST contain a <Subject> element.")
        val subject = subjects[0]

        val nameIds = subject.children("NameID")

        val bearerSubjectConfirmations = mutableListOf<Node>()
        subject.children("SubjectConfirmation")
                .filter { it.attributes.getNamedItem("Method").textContent == "urn:oasis:names:tc:SAML:2.0:cm:bearer" }
                .toCollection(bearerSubjectConfirmations)
        if (bearerSubjectConfirmations.isEmpty())
            throw SAMLComplianceException("Any assertion issued for consumption using this profile MUST contain a <Subject> element with at least one <SubjectConfirmation> element containing a Method of urn:oasis:names:tc:SAML:2.0:cm:bearer.")

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

        if (dataWithNotBefore > 0 && bearerSubjectConfirmationsData.isEmpty()) throw SAMLComplianceException("At lease one bearer <SubjectConfirmation> element MUST contain a <SubjectConfirmationData> element that itself MUST contain a Recipient attribute containing " +
                "the service provider's assertion consumer service URL and a NotOnOrAfter attribute that limits the window during which the assertion can be [E52]confirmed by the relying party. It MAY also contain an Address attribute limiting the client " +
                "address from which the assertion can be delivered. It MUST NOT contain a NotBefore attribute. If the containing message is in response to an <AuthnRequest>, then the InResponseTo attribute MUST match the request's Tests.ID.")

        if (authnStatements.isEmpty()) throw SAMLComplianceException("The set of one or more bearer assertions MUST contain at least one <AuthnStatement> that reflects the authentication of the principal to the identity provider.")

        if (IDP_METADATA != null) {
            if (IDP_METADATA.singleLogoutServices.isNotEmpty())
                authnStatements.forEach {
                    if (it.attributes.getNamedItem("SessionIndex") == null) throw SAMLComplianceException("If the identity provider supports the Single Logout profile, defined in Section 4.4, any authentication statements MUST include a SessionIndex attribute to " +
                            "enable per-session logout requests by the service provider.")
                }
        }

        // Assuming the AudienceRestriction is under Condition
        if (conditions.isNotEmpty()) {
            val audienceRestriction = conditions
                    .firstOrNull()
                    ?.children("AudienceRestriction")
                    ?.firstOrNull() ?: throw SAMLComplianceException("Each bearer assertion MUST contain an <AudienceRestriction> including the service provider's unique identifier as an <Audience>.")

            val audience = audienceRestriction.children("Audience").firstOrNull()
            if (audience == null || audience.textContent != SP_ISSUER) throw SAMLComplianceException("Each bearer assertion MUST contain an <AudienceRestriction> including the service provider's unique identifier as an <Audience>.")
        }
    }
}