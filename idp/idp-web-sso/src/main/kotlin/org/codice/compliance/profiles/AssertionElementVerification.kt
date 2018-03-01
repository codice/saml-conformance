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
package org.codice.compliance.profiles

import org.codice.compliance.*
import org.w3c.dom.Node

/**
 * Verify Assertion Elements against the profile document
 * 4.1.4.2 <Response> Usage
 */
fun verifySsoAssertions(response: Node) {
    if (response.children("Assertion").isEmpty()) throw SAMLComplianceException.create("SAMLProfiles.4.1.4.2_d")

    response.children("Assertion").forEach {
        verifyIssuer(it)

        if (it.children("Subject").size != 1) throw SAMLComplianceException.create("SAMLProfiles.4.1.4.2_g")

        val bearerSubjectConfirmations = mutableListOf<Node>()
        it.children("Subject")[0].children("SubjectConfirmation")
                .filter { it.attributes.getNamedItem("Method").textContent == "urn:oasis:names:tc:SAML:2.0:cm:bearer" }
                .toCollection(bearerSubjectConfirmations)
        if (bearerSubjectConfirmations.isEmpty())
            throw SAMLComplianceException.create("SAMLProfiles.4.1.4.2h")

        // Check if NotBefore is an attribute (it shouldn't)
        val dataWithNotBefore = bearerSubjectConfirmations
                .filter { it.children("SubjectConfirmationData").isNotEmpty() }
                .flatMap { it.children("SubjectConfirmationData") }
                .filter { it.attributes.getNamedItem("NotBefore") != null }
                .count()

        // Check if there is one SubjectConfirmationData with a Recipient, InResponseTo and NotOnOrAfter
        val bearerSubjectConfirmationsData = mutableListOf<Node>()
        bearerSubjectConfirmations
                .filter { it.children("SubjectConfirmationData").isNotEmpty() }
                .flatMap { it.children("SubjectConfirmationData") }
                .filter { it.attributes.getNamedItem("Recipient").textContent == ACS_URL }
                .filter { it.attributes.getNamedItem("InResponseTo").textContent == ID }
                .filter { it.attributes.getNamedItem("NotOnOrAfter") != null }
                .toCollection(bearerSubjectConfirmationsData)

        if (dataWithNotBefore > 0 && bearerSubjectConfirmationsData.isEmpty())
            throw SAMLComplianceException.create("SAMLProfiles.4.1.4.2_h")

        if (it.children("AuthnStatement").isEmpty()) throw SAMLComplianceException.create("SAMLProfiles.4.1.4.2_j")

        if (idpMetadata.descriptor != null) {
            if (idpMetadata.descriptor!!.singleLogoutServices.isNotEmpty())
                it.children("AuthnStatement").forEach {
                    if (it.attributes.getNamedItem("SessionIndex") == null) throw SAMLComplianceException.create("SAMLProfiles.4.1.4.2k")
                }
        }

        // Assuming the AudienceRestriction is under Conditions
        if (it.children("Conditions").isNotEmpty()) {
            val audienceRestriction = it.children("Conditions")
                    .firstOrNull()
                    ?.children("AudienceRestriction")
                    ?.firstOrNull()
                    ?: throw SAMLComplianceException.create("SAMLProfiles.4.1.4.2_l")

            if (audienceRestriction.children("Audience").firstOrNull()?.textContent != SP_ISSUER)
                throw SAMLComplianceException.create("SAMLProfiles.4.1.4.2_l")
        }
    }
}