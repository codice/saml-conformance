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
package org.codice.compliance.verification.core.responses

import io.restassured.response.Response
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_4_1_4_a
import org.codice.compliance.SAMLCore_3_4_1_4_b
import org.codice.compliance.SAMLCore_3_4_1_4_c
import org.codice.compliance.SAMLCore_3_4_1_4_d
import org.codice.compliance.SAMLCore_3_4_1_4_e
import org.codice.compliance.SAMLCore_3_4_1_a
import org.codice.compliance.SAMLCore_3_4_a
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.ASSERTION
import org.codice.compliance.utils.AUDIENCE
import org.codice.compliance.utils.AUTHN_STATEMENT
import org.codice.compliance.utils.NodeWrapper
import org.codice.compliance.utils.RESPONSE
import org.codice.compliance.utils.SUBJECT
import org.codice.compliance.utils.TestCommon.Companion.currentSPEntityInfo
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.compliance.utils.getLocation
import org.codice.compliance.verification.core.NameIDPolicyVerifier
import org.codice.compliance.verification.core.ResponseVerifier
import org.codice.compliance.verification.core.SubjectComparisonVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.opensaml.saml.saml2.core.AuthnRequest

class CoreAuthnRequestProtocolVerifier(private val authnRequest: AuthnRequest,
                                       samlResponse: NodeWrapper) :
        ResponseVerifier(authnRequest, samlResponse, HTTP_POST) {

    private val samlResponseDom = samlResponse.node

    private val nameIdPolicyVerifier =
            authnRequest.nameIDPolicy?.let { NameIDPolicyVerifier(samlResponseDom, it) }

    /** 3.4 Authentication Request Protocol **/
    override fun verify() {
        super.verify()
        verifyAuthnRequestProtocolResponse()
        verifySubjects()
        // TODO When DDF is fixed to return NameID format based on NameIDPolicy, uncomment this line
        //        nameIdPolicyVerifier?.apply { verify() }
    }

    fun verifyAssertionConsumerService(httpResponse: Response) {
        val expectedACS = currentSPEntityInfo.getAssertionConsumerService(authnRequest, null,
                authnRequest.assertionConsumerServiceIndex).url
        val actualACS = httpResponse.getLocation()

        if (actualACS == null || actualACS != expectedACS)
            throw SAMLComplianceException.create(SAMLCore_3_4_1_a,
                    message = "The URL at which the Response was received [$actualACS] does not" +
                            " match the expected ACS URL [$expectedACS] based on the request.")
    }

    private fun verifyAuthnRequestProtocolResponse() {
        val assertions = samlResponseDom.children(ASSERTION)

        if (samlResponseDom.localName != RESPONSE || assertions.isEmpty())
            throw SAMLComplianceException.create(SAMLCore_3_4_1_4_a,
                    message = "Did not find Response elements with one or more Assertion elements.",
                    node = samlResponseDom)

        if (assertions.all { it.children(AUTHN_STATEMENT).isEmpty() })
            throw SAMLComplianceException.create(SAMLCore_3_4_a, SAMLCore_3_4_1_4_d,
                    message = "AuthnStatement not found in any of the Assertions.",
                    node = samlResponseDom)

        if (assertions.any {
                    it.recursiveChildren("AudienceRestriction").flatMap { it.children(AUDIENCE) }
                            .none { it.textContent == currentSPIssuer }
                })
            throw SAMLComplianceException.create(SAMLCore_3_4_1_4_e,
                    message = "Assertion found without an AudienceRestriction referencing the " +
                            "requester.",
                    node = samlResponseDom)
    }

    override fun verifyEncryptedElements() {
        nameIdPolicyVerifier?.apply { verifyEncryptedIds() }
    }

    private fun verifySubjects() {
        samlResponseDom.recursiveChildren(ASSERTION).forEach {
            if (it.children(SUBJECT).isEmpty())
                throw SAMLComplianceException.create(SAMLCore_3_4_1_4_c,
                        message = "One of the Assertions contained no Subject",
                        node = it)
        }

        SubjectComparisonVerifier(samlResponseDom)
                .verifySubjectsMatchAuthnRequest(SAMLCore_3_4_1_4_b, authnRequest)
    }
}
