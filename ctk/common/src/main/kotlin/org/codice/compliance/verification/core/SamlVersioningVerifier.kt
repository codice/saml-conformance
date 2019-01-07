/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
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
import org.codice.compliance.report.Report
import org.codice.compliance.Section.CORE_4_1
import org.codice.compliance.Section.CORE_4_2
import org.codice.compliance.utils.ASSERTION
import org.codice.compliance.utils.VERSION
import org.opensaml.saml.common.SAMLVersion
import org.w3c.dom.Node

/** Only supports version 2.0 */
class SamlVersioningVerifier(private val samlResponseDom: Node) {
    companion object {
        private const val EXPECTED_MAJOR_VERSION = 2
    }

    /** 4 SAML Versioning */
    fun verify() {
        CORE_4_1.start()
        verifySetVersioning()
        verifyAssertionVersioning()

        CORE_4_2.start()
        verifyNamespaceVersioning()
    }

    /** 4.1 SAML Specification Set Version
     * Note: the version is already verified by the
     * {@link org.codice.compliance.verification.core.CommonDataTypeVerifier}
     **/
    private fun verifySetVersioning() {
        val version = samlResponseDom.attributeNode(VERSION)
        if (version == null || version.textContent.isBlank()) {
            CORE_4_1.skip()
            return
        }

        if (version.textContent != SAMLVersion.VERSION_20.toString()) {
            try {
                val responseMajorVersion = version.textContent.split(".").first().toInt()
                val codes = mutableListOf<SAMLSpecRefMessage>(SAMLCore_3_2_2_c, SAMLCore_4_1_3_3_a)

                if (responseMajorVersion < EXPECTED_MAJOR_VERSION) {
                    codes.add(SAMLCore_4_1_3_2_a)
                }
                if (responseMajorVersion > EXPECTED_MAJOR_VERSION) {
                    codes.add(SAMLCore_4_1_3_2_b)
                }

                Report.addExceptionMessage(SAMLComplianceException.createWithPropertyMessage(
                        SAMLCore_3_2_2_c,
                        property = VERSION,
                        actual = version.textContent,
                        expected = SAMLVersion.VERSION_20.toString(),
                        node = samlResponseDom))

                Report.addExceptionMessage(SAMLComplianceException.createWithPropertyMessage(codes,
                        property = VERSION,
                        actual = version.textContent,
                        expected = SAMLVersion.VERSION_20.toString(),
                        node = samlResponseDom), CORE_4_1)
            } catch (e: NumberFormatException) {
                CORE_4_1.skip()
                return
            }
        }
    }

    /** 4.1.2 SAML Assertion Version **/
    private fun verifyAssertionVersioning() {
        samlResponseDom.recursiveChildren(ASSERTION).forEach {
            val version = it.attributeNode(VERSION)
            if (version?.textContent != SAMLVersion.VERSION_20.toString()) {
                Report.addExceptionMessage(
                        SAMLComplianceException.createWithPropertyMessage(SAMLCore_2_3_3_a,
                                property = VERSION,
                                actual = version?.textContent,
                                expected = SAMLVersion.VERSION_20.toString(),
                                node = it))

                Report.addExceptionMessage(SAMLComplianceException.createWithPropertyMessage(
                        SAMLCore_4_1_2_a,
                        SAMLCore_2_3_3_a,
                        property = VERSION,
                        actual = version?.textContent,
                        expected = SAMLVersion.VERSION_20.toString(),
                        node = it), CORE_4_1)
            }
        }
    }

    /** 4.2 SAML Namespace Version **/
    @Suppress("ComplexCondition")
    private fun verifyNamespaceVersioning() {
        if (samlResponseDom.namespaceURI?.contains(SAMLVersion.VERSION_20.toString()) != true ||
                samlResponseDom.recursiveChildren()
                        .filter { it.namespaceURI != null && it.namespaceURI.contains("SAML") }
                        .any { !it.namespaceURI.contains(SAMLVersion.VERSION_20.toString()) }) {
            Report.addExceptionMessage(SAMLComplianceException.create(SAMLCore_4_2_a,
                    message = "A namespace URI with an incorrect version was found.",
                    node = samlResponseDom))
        }
    }
}
