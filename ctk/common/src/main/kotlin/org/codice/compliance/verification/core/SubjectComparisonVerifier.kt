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
package org.codice.compliance.verification.core

import com.google.common.collect.Sets
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_3_4_b
import org.codice.compliance.SAMLCore_3_3_4_c
import org.codice.compliance.SAMLCore_3_4_1_4_b
import org.codice.compliance.SAMLProfiles_4_1_4_2_d
import org.codice.compliance.SAMLProfiles_4_4_4_1_c
import org.codice.compliance.SAMLSpecRefMessage
import org.codice.compliance.attributeList
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.ASSERTION
import org.codice.compliance.utils.BASE_ID
import org.codice.compliance.utils.FORMAT
import org.codice.compliance.utils.METHOD
import org.codice.compliance.utils.NAME_ID
import org.codice.compliance.utils.SUBJECT
import org.codice.compliance.utils.SUBJECT_CONFIRMATION
import org.opensaml.saml.saml2.core.AuthnRequest
import org.w3c.dom.Node

/**
 * Verifies the samlRequest subjects **strongly match** the samlResponseDom subject according to the
 * Core document sections 3.3.4 & 3.4.1.4. (verifySubjectsMatchSSO)
 *
 * Verifies the samlResponseDom subjects refer to the same principal according to the Profiles
 * document section 4.1.4.2. (verifySubjectsMatchAuthnRequest)
 *
 * @param samlRequest Optional AuthnRequest {@code Node}. Should be passed when calling the
 * verifySubjectsMatchAuthnRequest method.
 * @param samlResponseDom Response {@code Node}.
 */
class SubjectComparisonVerifier(private val samlResponseDom: Node) {

    companion object {
        private const val UNSPECIFIED_URI =
                "urn:oasis:names:tc:SAML:2.0:nameid-format:unspecified"
        private const val EMPTY_STRING = ""
    }

    /**
     * This function verifies that all of the Subjects in the Response refer to the same principal.
     *
     * NOTE: This method does not actually resolve who the principal of the subject is. It only
     * tests that if two Subject identifiers have the same format, their content is the same. In
     * order to fully test this function we need to resolve the Subjects to a principal.
     */
    fun verifySubjectsMatchSSO() {
        val subjectSet = samlResponseDom.children(ASSERTION)
                .flatMap { it.children(SUBJECT) }
                .toSet()
        if (subjectSet.size < 2) return

        Sets.combinations(subjectSet, 2).forEach {
            verifyIdContentsMatch(it.first(), it.last(), SAMLProfiles_4_1_4_2_d)
        }
    }

    /**
     * Compares the text content of the identifiers. Special checking due to nameIdPolicyFormat.
     */
    private fun verifyIdContentsMatch(id1: Node, id2: Node, samlCode: SAMLSpecRefMessage) {
        val format1 = id1.filteredFormatValue
        val format2 = id2.filteredFormatValue

        // If they share a format value that isn't "unspecified", but have different contents
        if (format1 == format2
                && format1 != null
                && id1.textContent != id2.textContent) {
            throw SAMLComplianceException.create(SAMLCore_3_3_4_b,
                    samlCode,
                    message = "The identifiers have identical Format attributes " +
                            "[$format1], but the content of one [${id1.textContent}] is not " +
                            "equal to the content of the other [${id2.textContent}]",
                    node = samlResponseDom)
        }
    }

    /**
     * This function verifies that the identifier in the LogoutRequest strongly matches
     * the identifier from the SAML assertion that was issued when that principal was logged in.
     */
    fun verifyIdsMatchSLO(logoutRequest: Node) {
        val assertionId =
                samlResponseDom.recursiveChildren(ASSERTION).firstOrNull()?.children(SUBJECT)
                        ?.firstOrNull()?.id ?: throw IllegalArgumentException(
                        "Could not find the assertion's identifier on the response.")

        val logoutRequestId = logoutRequest.children().firstOrNull {
            it.localName == NAME_ID || it.localName == BASE_ID
        } ?: throw IllegalArgumentException(
                "Could not find the logout request's identifier.")

//        verifyIdAttributesMatch(assertionId, logoutRequestId, SAMLProfiles_4_4_4_1_c)
        verifyIdContentsMatch(assertionId, logoutRequestId, SAMLProfiles_4_4_4_1_c)
    }

    /**
     * This function verifies that the Subjects from the Response **strongly match** the Subject
     * from the AuthnRequest.
     *
     * NOTE: This method does not test to make sure the Response Subject's identifier's Format is
     * equal to an optional NameIDPolicyFormat from the AuthnRequest. That is tested in
     * NameIDPolicyVerifier
     *
     * NOTE: This method does not actually resolve who the principal of the subject is. It only
     * compares the given Subject values to each other. In order to fully test this function we
     * need to resolve the Subjects to a principal.
     */
    @Suppress("NestedBlockDepth" /* Simple `let` nesting */)
    fun verifySubjectsMatchAuthnRequest(samlCode: SAMLSpecRefMessage, authnRequest: AuthnRequest) {

        val requestSubject = authnRequest.dom?.children(SUBJECT)?.firstOrNull() ?: return
        val requestId = requestSubject.id
        val requestConfirmations = requestSubject.children(SUBJECT_CONFIRMATION)

        if (requestId == null && requestConfirmations.isEmpty()) return

        val nameIdPolicyFormat =
                authnRequest.dom?.children("NameIDPolicy")?.firstOrNull()?.filteredFormatValue

        samlResponseDom.recursiveChildren(ASSERTION)
                .flatMap { it.children(SUBJECT) }
                .forEach { resSubject ->

                    // Verify ids match
                    requestId?.let { reqId ->
                        resSubject.id?.let { resId ->
                            verifyIdAttributesMatch(reqId, resId, SAMLCore_3_4_1_4_b,
                                    nameIdPolicyFormat)
                            verifyIdContentsMatch(reqId, resId, SAMLCore_3_4_1_4_b)
                        } ?: throw SAMLComplianceException.create(samlCode,
                                SAMLCore_3_3_4_b,
                                message = "One of the Response's Subjects contained no identifier",
                                node = resSubject)
                    }

                    // Verify SubjectConfirmations match
                    requestConfirmations.let { reqConfirmations ->
                        resSubject.children(SUBJECT_CONFIRMATION).let { resConfirmations ->
                            if (resConfirmations.isEmpty())
                                throw SAMLComplianceException.create(samlCode,
                                        SAMLCore_3_3_4_c,
                                        message = "One of the Response's Subjects contained no " +
                                                "SubjectConfirmations.",
                                        node = resSubject)
                            verifyConfirmationsMatchAuthnRequest(reqConfirmations,
                                    resConfirmations)
                        }
                    }
                }
    }

    /**
     * Compares all of the attributes of the identifiers. Special checking for the Format attribute.
     */
    private fun verifyIdAttributesMatch(id1: Node,
                                        id2: Node,
                                        samlCode: SAMLSpecRefMessage,
                                        nameIdPolicyFormat: String? = null) {
        // Check the format attribute separately
        /*
         * If no NameIDPolicyFormat is defined, the Request format and the Response format are
         * different, and the formats are not unspecified
         */
        if (nameIdPolicyFormat == null) {
            val format1 = id1.filteredFormatValue
            val format2 = id2.filteredFormatValue
            if (format1 != null && format1 != format2)
                throw SAMLComplianceException.create(SAMLCore_3_3_4_b,
                        message = "One of the identifier's Format attribute " +
                                "[${format2 ?: UNSPECIFIED_URI}] is not identical to the " +
                                "AuthnRequest's Subject identifier's Format attribute " +
                                "[$format1].",
                        node = id2)
        }

        val attributes1 = id1.attributeList().filter { it.localName != FORMAT }.toSet()
        val attributes2 = id2.attributeList().filter { it.localName != FORMAT }.toSet()

        if (attributes1 != attributes2)
            throw SAMLComplianceException.create(SAMLCore_3_3_4_b,
                    samlCode,
                    message = "One of the identifier's attributes " +
                            "[$attributes2] are not identical to another" +
                            " identifier's attributes [$attributes1].",
                    node = id2)
    }

    /**
     * Verifies that the samlRequest SubjectConfirmations **strongly match** the samlResponseDom
     * confirmations.
     *
     * Note that this matching only compares the methods of the SubjectConfirmations. In order to
     * properly strongly match we would need to "confirm" the SubjectConfirmation (Hard To Test)
     */
    private fun verifyConfirmationsMatchAuthnRequest(requestConfirmations: List<Node>,
                                                     responseConfirmations: List<Node>) {

        val requestMethods = requestConfirmations
                .mapNotNull { it.attributeText(METHOD) }.toSet()
        val responseMethods = responseConfirmations
                .mapNotNull { it.attributeText(METHOD) }.toSet()

        // If none of the Request SubjectConfirmations have any matching Response
        // SubjectConfirmations
        if (requestMethods.none { reqMethod ->
                    responseMethods.contains(reqMethod)
                }
        ) throw SAMLComplianceException.create(SAMLCore_3_3_4_c,
                SAMLCore_3_4_1_4_b,
                message = "One of the Response's Subjects had no SubjectConfirmation Methods " +
                        "[$responseMethods] matching the AuthnRequest's SubjectConfirmation " +
                        "Methods [$requestMethods].",
                node = samlResponseDom)
    }

    /**
     * Returns the Format attribute value if it isn't empty or "unspecified". Else returns null.
     *
     * @param node The {@code Node} attribute to check the format value on
     * @return The filtered Format attribute value
     */
    private val Node.filteredFormatValue: String?
        get() = this.attributeText(FORMAT)?.let {
            when (it) {
                EMPTY_STRING -> null
                UNSPECIFIED_URI -> null
                else -> it
            }
        }

    /**
     * Since the identifier is an extensible element and the xml schema defines that there can
     * only be one identifier plus any number of SubjectConfirmations, we pull off the first thing
     * that isn't a SubjectConfirmation element.
     */
    private val Node.id: Node?
        get() = this.children().firstOrNull { it.localName != SUBJECT_CONFIRMATION }
}
