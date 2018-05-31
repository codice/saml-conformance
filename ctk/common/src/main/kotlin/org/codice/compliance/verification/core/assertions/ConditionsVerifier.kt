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
package org.codice.compliance.verification.core.assertions

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_2_5_1_2_a
import org.codice.compliance.SAMLCore_2_5_1_5_a
import org.codice.compliance.SAMLCore_2_5_1_6_a
import org.codice.compliance.SAMLCore_2_5_1_6_b
import org.codice.compliance.SAMLCore_2_5_1_a
import org.codice.compliance.SAMLCore_2_5_1_b
import org.codice.compliance.SAMLCore_2_5_1_c
import org.codice.compliance.attributeNodeNS
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.AUDIENCE
import org.codice.compliance.utils.XSI
import org.codice.compliance.verification.core.CommonDataTypeVerifier
import org.codice.compliance.verification.core.CoreVerifier.Companion.validateTimeWindow
import org.w3c.dom.Node

internal class ConditionsVerifier(val node: Node) {

    /** 2.5 Conditions */
    fun verify() {
        node.recursiveChildren("Conditions").forEach {
            verifyConditions(it)
            verifyAudience(it)
            verifyProxyRestrictions(it)
        }
    }

    /**
     * 2.5.1 Element <Conditions>
     * 2.5.1.2 Attributes NotBefore and NotOnOrAfter
     * 2.5.1.5 Element <OneTimeUse>
     */
    private fun verifyConditions(conditionsElement: Node) {

        validateTimeWindow(conditionsElement, SAMLCore_2_5_1_2_a)

        if (conditionsElement.children("Condition")
                        .any { it.attributeNodeNS(XSI, "type") == null })
            throw SAMLComplianceException.create(SAMLCore_2_5_1_a,
                    message = "Condition found without a type.",
                    node = node)

        if (conditionsElement.children("OneTimeUse").size > 1)
            throw SAMLComplianceException.create(SAMLCore_2_5_1_b, SAMLCore_2_5_1_5_a,
                    message = "Cannot have more than one OneTimeUse element.",
                    node = node)

        if (conditionsElement.children("ProxyRestriction").size > 1)
            throw SAMLComplianceException.create(SAMLCore_2_5_1_c, SAMLCore_2_5_1_6_b,
                    message = "Cannot have more than one ProxyRestriction element.",
                    node = node)
    }

    /** 2.5.1.4 Elements <AudienceRestriction> and <Audience> */
    private fun verifyAudience(conditionsElement: Node) {
        conditionsElement.children("AudienceRestriction")
                .filter { it.children(AUDIENCE).isNotEmpty() }
                .flatMap { it.children(AUDIENCE) }
                .forEach { CommonDataTypeVerifier.verifyUriValue(it) }
    }

    /** 2.5.1.6 Element <ProxyRestriction> */
    private fun verifyProxyRestrictions(conditionsElement: Node) {
        val proxyRestrictionAudiences = conditionsElement.children("ProxyRestriction")
                .filter { it.children(AUDIENCE).isNotEmpty() }
                .flatMap { it.children(AUDIENCE) }
                .map { it.textContent }
                .toList()
        if (proxyRestrictionAudiences.isEmpty()) return

        val audienceRestrictions = conditionsElement.recursiveChildren("AudienceRestriction")
        if (audienceRestrictions.isEmpty()) throw SAMLComplianceException.create(SAMLCore_2_5_1_6_a,
                message = "There must be an AudienceRestriction element.",
                node = node)

        audienceRestrictions.forEach {
            val audienceRestrictionAudiences = it.children(AUDIENCE)
            if (audienceRestrictionAudiences.isEmpty())
                throw SAMLComplianceException.create(SAMLCore_2_5_1_6_a,
                        message = "The AudienceRestriction element must contain at least one " +
                                "Audience element.",
                        node = node)

            if (it.children(AUDIENCE).any { !proxyRestrictionAudiences.contains(it.textContent) })
                throw SAMLComplianceException.create(SAMLCore_2_5_1_6_a,
                        message = "The AudienceRestriction can only have Audience elements " +
                                "that are also in the ProxyRestriction element.",
                        node = node)
        }
    }
}
