/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.core.responses

import io.restassured.response.Response
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_3_2_2_1_a
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
import org.codice.compliance.utils.NodeDecorator
import org.codice.compliance.utils.RESPONSE
import org.codice.compliance.utils.SUBJECT
import org.codice.compliance.utils.TestCommon.Companion.currentSPEntityInfo
import org.codice.compliance.utils.TestCommon.Companion.currentSPIssuer
import org.codice.compliance.utils.ddfAuthnContextList
import org.codice.compliance.utils.getLocation
import org.codice.compliance.verification.core.NameIDPolicyVerifier
import org.codice.compliance.verification.core.ResponseVerifier
import org.codice.compliance.verification.core.SubjectComparisonVerifier
import org.codice.security.saml.SamlProtocol.Binding.HTTP_POST
import org.opensaml.saml.saml2.core.AuthnRequest

class CoreAuthnRequestProtocolVerifier(
    private val authnRequest: AuthnRequest,
    private val samlResponse: NodeDecorator
) :
        ResponseVerifier(authnRequest, samlResponse, HTTP_POST) {

    private val nameIdPolicyVerifier =
            authnRequest.nameIDPolicy?.let {
                NameIDPolicyVerifier(
                        this.samlResponse, it)
            }

    /** 3.4 Authentication Request Protocol **/
    override fun verify() {
        super.verify()
        verifyAuthnRequestProtocolResponse()
        verifySubjects()
        nameIdPolicyVerifier?.verify()
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

    fun verifyAuthnContextClassRef() {
        samlResponse.recursiveChildren("AuthnContext")
                .flatMap { it.children("AuthnContextClassRef") }
                .firstOrNull { !ddfAuthnContextList.contains(it.textContent) }?.let {
                    throw SAMLComplianceException.create(SAMLCore_3_3_2_2_1_a,
                            message = """An <AuthnContextClassRef> that is not part of the
                                    requested <AuthnContextClassRef>s was found. The requested
                                    <AuthnContextClassRef>s are
                                    ${ddfAuthnContextList.joinToString()}.""",
                            node = it)
                }
    }

    private fun verifyAuthnRequestProtocolResponse() {
        val assertions = samlResponse.children(ASSERTION)

        if (samlResponse.localName != RESPONSE || assertions.isEmpty())
            throw SAMLComplianceException.create(SAMLCore_3_4_1_4_a,
                    message = "Did not find Response elements with one or more Assertion elements.",
                    node = samlResponse)

        if (assertions.all { it.children(AUTHN_STATEMENT).isEmpty() })
            throw SAMLComplianceException.create(SAMLCore_3_4_a, SAMLCore_3_4_1_4_d,
                    message = "AuthnStatement not found in any of the Assertions.",
                    node = samlResponse)

        if (assertions.any {
                    it.recursiveChildren("AudienceRestriction").flatMap { it.children(AUDIENCE) }
                            .none { it.textContent == currentSPIssuer }
                })
            throw SAMLComplianceException.create(SAMLCore_3_4_1_4_e,
                    message = "Assertion found without an AudienceRestriction referencing the " +
                            "requester.",
                    node = samlResponse)
    }

    override fun verifyEncryptedElements() {
        nameIdPolicyVerifier?.apply { verifyEncryptedIds() }
    }

    private fun verifySubjects() {
        samlResponse.recursiveChildren(ASSERTION).forEach {
            if (it.children(SUBJECT).isEmpty())
                throw SAMLComplianceException.create(SAMLCore_3_4_1_4_c,
                        message = "One of the Assertions contained no Subject",
                        node = it)
        }

        SubjectComparisonVerifier(samlResponse)
                .verifySubjectsMatchAuthnRequest(SAMLCore_3_4_1_4_b, authnRequest)
    }
}
