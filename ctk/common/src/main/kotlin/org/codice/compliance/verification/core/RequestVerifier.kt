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

import org.codice.compliance.SAMLCore_3_2_1_a
import org.codice.compliance.SAMLCore_3_2_1_b
import org.codice.compliance.SAMLCore_3_2_1_c
import org.codice.compliance.attributeNode
import org.codice.compliance.utils.TestCommon.Companion.ID
import org.codice.compliance.utils.TestCommon.Companion.VERSION
import org.w3c.dom.Node

abstract class RequestVerifier(private val samlRequestDom: Node) : CoreVerifier(samlRequestDom) {

    /** 3.2.1 Complex Type RequestAbstractType */
    override fun verify() {
        verifyRequestAbstractType()
        super.verify()
    }

    /** All SAML requests are of types that are derived from the abstract RequestAbstractType
     * complex type. */
    private fun verifyRequestAbstractType() {
        CommonDataTypeVerifier.verifyIdValue(samlRequestDom.attributeNode(ID), SAMLCore_3_2_1_a)
        CommonDataTypeVerifier.verifyStringValue(samlRequestDom.attributeNode(VERSION),
            SAMLCore_3_2_1_b)
        CommonDataTypeVerifier.verifyDateTimeValue(
            samlRequestDom.attributeNode("IssueInstant"), SAMLCore_3_2_1_c)

        samlRequestDom.attributeNode("Destination")?.let {
            CommonDataTypeVerifier.verifyUriValue(it)
        }

        samlRequestDom.attributeNode("Consent")?.let {
            CommonDataTypeVerifier.verifyUriValue(it)
        }
    }
}
