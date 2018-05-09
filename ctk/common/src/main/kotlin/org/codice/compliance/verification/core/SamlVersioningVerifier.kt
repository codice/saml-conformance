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
import org.codice.compliance.SAMLCore_2_3_3_a
import org.codice.compliance.SAMLCore_3_2_2_c
import org.codice.compliance.SAMLCore_4_1_2_a
import org.codice.compliance.SAMLCore_4_1_3_2_a
import org.codice.compliance.SAMLCore_4_1_3_2_b
import org.codice.compliance.SAMLCore_4_1_3_3_a
import org.codice.compliance.SAMLCore_4_2_a
import org.codice.compliance.SAMLSpecRefMessage
import org.codice.compliance.attributeNode
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon
import org.opensaml.saml.common.SAMLVersion
import org.w3c.dom.Node

/** Only supports version 2.0 */
class SamlVersioningVerifier(private val samlResponseDom: Node) {
    companion object {
        private const val EXPECTED_MAJOR_VERSION = 2
    }

    /** 4 SAML Versioning */
    fun verify() {
        verifySetVersioning()
        verifyAssertionVersioning()
        verifyNamespaceVersioning()
    }

    /** 4.1 SAML Specification Set Version **/
    @Suppress("SpreadOperator")
    private fun verifySetVersioning() {
        val version = samlResponseDom.attributeNode(TestCommon.VERSION)
        if (version?.textContent != SAMLVersion.VERSION_20.toString()) {

            val responseMajorVersion = version?.textContent?.split(".")?.first()?.toInt()
            val codes = mutableListOf<SAMLSpecRefMessage>(SAMLCore_3_2_2_c, SAMLCore_4_1_3_3_a)

            if (responseMajorVersion != null) {
                if (responseMajorVersion < EXPECTED_MAJOR_VERSION) codes.add(SAMLCore_4_1_3_2_a)
                if (responseMajorVersion > EXPECTED_MAJOR_VERSION) codes.add(SAMLCore_4_1_3_2_b)
            }

            throw SAMLComplianceException.createWithPropertyMessage(*codes.toTypedArray(),
                property = TestCommon.VERSION,
                actual = version?.textContent,
                expected = SAMLVersion.VERSION_20.toString(),
                node = samlResponseDom)
        }
    }

    /** 4.1.2 SAML Assertion Version **/
    private fun verifyAssertionVersioning() {
        samlResponseDom.recursiveChildren(TestCommon.ASSERTION).forEach {
            val version = it.attributeNode(TestCommon.VERSION)
            if (version?.textContent != SAMLVersion.VERSION_20.toString())
                throw SAMLComplianceException.createWithPropertyMessage(SAMLCore_2_3_3_a,
                    SAMLCore_4_1_2_a,
                    property = TestCommon.VERSION,
                    actual = version?.textContent,
                    expected = SAMLVersion.VERSION_20.toString(),
                    node = it)
        }
    }

    /** 4.2 SAML Namespace Version **/
    @Suppress("ComplexCondition")
    private fun verifyNamespaceVersioning() {
        if (samlResponseDom.namespaceURI?.contains(SAMLVersion.VERSION_20.toString()) != true ||
            samlResponseDom.recursiveChildren()
                .filter { it.namespaceURI != null && it.namespaceURI.contains("SAML") }
                .any { !it.namespaceURI.contains(SAMLVersion.VERSION_20.toString()) })
            throw SAMLComplianceException.create(SAMLCore_4_2_a,
                message = "A namespace URI with an incorrect version was found.",
                node = samlResponseDom)
    }
}
