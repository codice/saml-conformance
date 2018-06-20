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
package org.codice.compliance.verification.binding

import io.restassured.response.Response
import org.apache.wss4j.common.saml.OpenSAMLUtil
import org.codice.compliance.SAMLBindings_3_4_6_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLGeneral_b
import org.codice.compliance.utils.NodeWrapper
import org.codice.compliance.SAMLProfiles_4_4_4_1_b
import org.codice.compliance.SAMLProfiles_4_4_4_2_b
import org.codice.compliance.utils.LOGOUT_REQUEST
import org.codice.compliance.utils.LOGOUT_RESPONSE
import org.codice.compliance.utils.RESPONSE
import org.codice.compliance.utils.sign.SimpleSign
import org.opensaml.saml.saml2.core.RequestAbstractType
import org.opensaml.saml.saml2.core.StatusResponseType
import org.w3c.dom.Node

abstract class BindingVerifier(val httpResponse: Response) {
    companion object {
        private const val HTTP_ERROR_THRESHOLD = 400

        /**
         * Verifies the http status code of the response is not an error status code
         * according to the binding spec
         * 3.4.6 & 3.5.6 Error Reporting
         */
        fun verifyHttpStatusCode(code: Int) {
            if (isErrorHttpStatusCode(code)) {
                throw SAMLComplianceException.createWithPropertyMessage(
                        SAMLBindings_3_4_6_a,
                        property = "HTTP Status Code",
                        actual = code.toString(),
                        expected = "a non-error http status code; i.e. less than " +
                                HTTP_ERROR_THRESHOLD)
            }
        }

        /**
         * Verifies if the http status code is an error status code.
         */
        fun isErrorHttpStatusCode(code: Int): Boolean {
            return code >= HTTP_ERROR_THRESHOLD
        }

        /**
         * Verifies the response's and assertions' signatures.
         * Returns true if the SAML message is signed. Returns false, otherwise.
         * */
        @Suppress("SpreadOperator", "ComplexMethod")
        fun verifyXmlSignatures(node: Node): Boolean {
            try {
                val docElement = node.ownerDocument.documentElement

                val samlResponseObject =
                        if (node.nodeName.contains(RESPONSE))
                            OpenSAMLUtil.fromDom(docElement) as StatusResponseType
                        else OpenSAMLUtil.fromDom(docElement) as RequestAbstractType

                if (samlResponseObject.isSigned)
                    SimpleSign().validateSignature(samlResponseObject.signature)

                if (samlResponseObject is org.opensaml.saml.saml2.core.Response) {
                    samlResponseObject.assertions
                            .filter { it.isSigned }
                            .forEach { SimpleSign().validateSignature(it.signature) }
                }

                return samlResponseObject.isSigned
            } catch (e: SimpleSign.SignatureException) {
                val errorCodes = when (node.localName) {
                    LOGOUT_REQUEST -> arrayOf(SAMLGeneral_b, SAMLProfiles_4_4_4_1_b)
                    LOGOUT_RESPONSE -> arrayOf(SAMLGeneral_b, SAMLProfiles_4_4_4_2_b)
                    else -> arrayOf(SAMLGeneral_b)
                }

                throw SAMLComplianceException.create(*errorCodes,
                        message = "Invalid signature.\n${e.message}",
                        cause = e)
            }
        }
    }

    var isSamlRequest: Boolean = false
    var isRelayStateGiven: Boolean = false
    abstract fun decodeAndVerifyError(): Node
    abstract fun decodeAndVerify(): NodeWrapper
}
