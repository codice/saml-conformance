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

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_3_3_4_b
import org.codice.compliance.SAMLCore_3_3_4_c
import org.codice.compliance.SAMLCore_3_4_1_4_b
import org.codice.compliance.SAMLProfiles_4_1_4_2_e
import org.codice.compliance.attributeList
import org.codice.compliance.attributeText
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon.Companion.FORMAT
import org.codice.compliance.utils.TestCommon.Companion.SUBJECT
import org.codice.compliance.utils.TestCommon.Companion.SUBJECT_CONFIRMATION
import org.w3c.dom.Node

/**
 * Verifies the request subjects **strongly match** the response subject according to the Core
 * document sections 3.3.4 & 3.4.1.4. (verifySubjectsMatchSSO)
 *
 * Verifies the response subjects refer to the same principal according to the Profiles document
 * section 4.1.4.2. (verifySubjectsMatchAuthnRequest)
 *
 * @param request Optional AuthnRequest {@code Node}. Should be passed when calling the
 * verifySubjectsMatchAuthnRequest method.
 * @param response Response {@code Node}.
 */
class SubjectComparisonVerifier(private val request: Node? = null, private val response: Node) {

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
        val subjectList = response.children("Assertion")
                .flatMap { it.children(SUBJECT) }
                .toList()

        subjectList.forEachIndexed { index, outerSubject ->
            subjectList.subList(index + 1, subjectList.size).forEach { innerSubject ->
                verifyIdContentsMatchSSO(outerSubject, innerSubject)
            }
        }
    }

    /**
     * Compares the text content of the identifiers. Special checking due to nameIdPolicyFormat.
     */
    private fun verifyIdContentsMatchSSO(id1: Node, id2: Node) {
        val format1 = id1.filteredFormatValue()
        val format2 = id2.filteredFormatValue()

        // If they share a format value that isn't "unspecified", but have different contents
        if (format1 == format2
                && format1 != null
                && id1.textContent != id2.textContent) {
            throw SAMLComplianceException.create(SAMLProfiles_4_1_4_2_e,
                    SAMLCore_3_3_4_b,
                    message = "Two Response Subject identifiers have identical Format attributes " +
                            "[$format1], but the content of one [${id1.textContent}] is not " +
                            "equal to the content of the other [${id2.textContent}]",
                    node = response)
        }
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
    fun verifySubjectsMatchAuthnRequest() {

        val requestSubject = request?.children("Subject")?.firstOrNull() ?: return
        val requestId = requestSubject.getId()
        val requestConfirmations = requestSubject.children(SUBJECT_CONFIRMATION)

        if (requestId == null && requestConfirmations.isEmpty()) return

        val nameIdPolicyFormat =
                request.children("NameIDPolicy").firstOrNull()?.filteredFormatValue()

        response.recursiveChildren("Assertion")
                .flatMap { it.children(SUBJECT) }
                .forEach { resSubject ->

                    // Verify ids match
                    requestId?.let { reqId ->
                        resSubject.getId()?.let { resId ->
                            verifyIdAttributesMatchAuthnRequest(reqId, resId, nameIdPolicyFormat)
                            verifyIdContentsMatchAuthnRequest(reqId, resId)
                        } ?: throw SAMLComplianceException.create(
                                SAMLCore_3_3_4_b,
                                SAMLCore_3_4_1_4_b,
                                message = "One of the Response's Subjects contained no identifier",
                                node = resSubject)
                    }

                    // Verify SubjectConfirmations match
                    requestConfirmations.let { reqConfirmations ->
                        resSubject.children(SUBJECT_CONFIRMATION).let { resConfirmations ->
                            if (resConfirmations.isEmpty())
                                throw SAMLComplianceException.create(
                                        SAMLCore_3_3_4_c,
                                        SAMLCore_3_4_1_4_b,
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
    private fun verifyIdAttributesMatchAuthnRequest(reqId: Node,
                                                    resId: Node,
                                                    nameIdPolicyFormat: String? = null) {
        // Check the format attribute separately
        /*
         * If no NameIDPolicyFormat is defined, the Request format and the Response format are
         * different, and the formats are not unspecified
         */
        if (nameIdPolicyFormat == null) {
            val reqFormat = reqId.filteredFormatValue()
            val resFormat = resId.filteredFormatValue()
            if (reqFormat != null && reqFormat != resFormat)
                throw SAMLComplianceException.create(SAMLCore_3_3_4_b,
                        message = "One of the Response's Subject identifier's Format attribute " +
                                "[${resFormat ?: UNSPECIFIED_URI}] is not identical to the " +
                                "AuthnRequest's Subject identifier's Format attribute " +
                                "[$reqFormat].",
                        node = resId)
        }

        val reqAttributes = reqId.attributeList().filter { it.localName != FORMAT }.toSet()
        val resAttributes = resId.attributeList().filter { it.localName != FORMAT }.toSet()

        if (reqAttributes != resAttributes)
            throw SAMLComplianceException.create(SAMLCore_3_3_4_b,
                    SAMLCore_3_4_1_4_b,
                    message = "One of the Response's Subject identifier's attributes " +
                            "[$resAttributes] are not identical to the" +
                            "AuthnRequest's Subject identifier's attributes [$reqAttributes].",
                    node = resId)
    }

    /**
     * Compares the text content of the identifiers. Special checking due to nameIdPolicyFormat.
     */
    private fun verifyIdContentsMatchAuthnRequest(reqId: Node, resId: Node) {
        val reqFormat = reqId.filteredFormatValue()
        val resFormat = resId.filteredFormatValue()

        // If they share a format value that isn't "unspecified", but have different contents
        if (reqFormat == resFormat
                && reqFormat != null
                && reqId.textContent != resId.textContent) {
            throw SAMLComplianceException.create(SAMLCore_3_3_4_b,
                    SAMLCore_3_4_1_4_b,
                    message = "One of the Response's Subject identifier's content " +
                            "[${resId.textContent}] is not identical to the AuthnRequest's " +
                            "Subject identifier's content [${reqId.textContent}], even though " +
                            "they share the same identifier format [$reqFormat].",
                    node = resId)
        }
    }

    /**
     * Verifies that the request SubjectConfirmations **strongly match** the response confirmations.
     *
     * Note that this matching only compares the methods of the SubjectConfirmations. In order to
     * properly strongly match we would need to "confirm" the SubjectConfirmation (Hard To Test)
     */
    private fun verifyConfirmationsMatchAuthnRequest(requestConfirmations: List<Node>,
                                                     responseConfirmations: List<Node>) {

        val requestMethods = requestConfirmations
                .mapNotNull { it.attributeText("Method") }.toSet()
        val responseMethods = responseConfirmations
                .mapNotNull { it.attributeText("Method") }.toSet()

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
                node = response)
    }

    /**
     * Returns the Format attribute value if it isn't empty or "unspecified". Else returns null.
     *
     * @param node The {@code Node} attribute to check the format value on
     * @return The filtered Format attribute value
     */
    private fun Node.filteredFormatValue(): String? {
        return this.attributeText(FORMAT)?.let {
            when (it) {
                EMPTY_STRING -> null
                UNSPECIFIED_URI -> null
                else -> it
            }
        }
    }

    /**
     * Since the identifier is an extensible element and the xml schema defines that there can
     * only be one identifier plus any number of SubjectConfirmations, we pull off the first thing
     * that isn't a SubjectConfirmation element.
     */
    private fun Node.getId(): Node? {
        return this.children().firstOrNull { it.localName != SUBJECT_CONFIRMATION }
    }
}
