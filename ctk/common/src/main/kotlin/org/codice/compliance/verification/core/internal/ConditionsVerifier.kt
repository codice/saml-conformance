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
package org.codice.compliance.verification.core.internal

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_2_5_1_2
import org.codice.compliance.SAMLCore_2_5_1_5
import org.codice.compliance.SAMLCore_2_5_1_6_a
import org.codice.compliance.SAMLCore_2_5_1_6_b
import org.codice.compliance.SAMLCore_2_5_1_a
import org.codice.compliance.SAMLCore_2_5_1_b
import org.codice.compliance.SAMLCore_2_5_1_c
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.codice.compliance.utils.TestCommon
import org.w3c.dom.Node
import java.time.Instant

internal class ConditionsVerifier(val node: Node) {
    companion object {
        private const val AUDIENCE = "Audience"
    }

    fun verify() {
        node.allChildren("Conditions").forEach {
            verifyConditionAttributes(it)
            verifyConditionType(it)
            verifyOneTimeUse(it)
            verifyProxyRestrictions(it)
        }
    }

    /**
     * Verify the <Conditions> element against the Core Spec
     * 2.5.1 Element <Conditions>
     * 2.5.1.2 Attributes NotBefore and NotOnOrAfter
     * 2.5.1.5 Element <OneTimeUse>
     * 2.5.1.6 Element <ProxyRestriction>
     */
    private fun verifyConditionAttributes(conditionsElement: Node) {
        val notBefore = conditionsElement.attributes.getNamedItem("NotBefore")
        val notOnOrAfter = conditionsElement.attributes.getNamedItem("NotOnOrAfter")
        if (notBefore != null
                && notOnOrAfter != null) {
            val notBeforeValue = Instant.parse(notBefore.textContent)
            val notOnOrAfterValue = Instant.parse(notOnOrAfter.textContent)
            if (notBeforeValue.isAfter(notOnOrAfterValue))
                throw SAMLComplianceException.create(SAMLCore_2_5_1_2,
                        message = "NotBefore element with value $notBeforeValue is not less than " +
                                "NotOnOrAfter element with value $notOnOrAfterValue.",
                        node = node)
        }
    }

    private fun verifyConditionType(conditionsElement: Node) {
        if (conditionsElement.children("Condition")
                        .any { it.attributes.getNamedItemNS(TestCommon.XSI, "type") == null })
            throw SAMLComplianceException.create(SAMLCore_2_5_1_a,
                    message = "Condition found without a type.",
                    node = node)
    }

    private fun verifyOneTimeUse(conditionsElement: Node) {
        if (conditionsElement.children("OneTimeUse").size > 1)
            throw SAMLComplianceException.create(SAMLCore_2_5_1_b, SAMLCore_2_5_1_5,
                    message = "Cannot have more than one OneTimeUse element.",
                    node = node)
    }

    private fun verifyProxyRestrictions(conditionsElement: Node) {
        val proxyRestrictions = conditionsElement.children("ProxyRestriction")
        if (!proxyRestrictions.isNotEmpty()) return

        if (proxyRestrictions.size > 1)
            throw SAMLComplianceException.create(SAMLCore_2_5_1_c, SAMLCore_2_5_1_6_b,
                    message = "Cannot have more than one ProxyRestriction element.",
                    node = node)

        val proxyRestrictionAudiences = proxyRestrictions
                .flatMap { it.children(AUDIENCE) }
                .map { it.textContent }
                .toList()

        if (!proxyRestrictionAudiences.isNotEmpty()) return

        val audienceRestrictions = conditionsElement.allChildren("AudienceRestriction")

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
            it.children(AUDIENCE).forEach {
                if (!proxyRestrictionAudiences.contains(it.textContent))
                    throw SAMLComplianceException.create(SAMLCore_2_5_1_6_a,
                            message = "The AudienceRestriction can only have Audience elements " +
                                    "that are also in the ProxyRestriction element.",
                            node = node)
            }
        }
    }
}
