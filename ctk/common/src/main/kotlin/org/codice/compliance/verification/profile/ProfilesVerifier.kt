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
package org.codice.compliance.verification.profile

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLProfiles_4_1_4_2_l
import org.codice.compliance.SAMLSpecRefMessage
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.ASSERTION
import org.w3c.dom.Node

class ProfilesVerifier {
    companion object {
        /**
         * Verify Error Response against the Profiles document.
         * This should be called explicitly if an error is expected.
         */
        fun verifyErrorResponseAssertion(node: Node, samlErrorCode: SAMLSpecRefMessage? = null) {
            if (node.recursiveChildren(ASSERTION).isNotEmpty()) {
                val exceptions: Array<SAMLSpecRefMessage> =
                    if (samlErrorCode != null)
                        arrayOf(samlErrorCode, SAMLProfiles_4_1_4_2_l)
                    else
                        arrayOf(SAMLProfiles_4_1_4_2_l)

                @Suppress("SpreadOperator")
                throw SAMLComplianceException.create(*exceptions,
                    message = "A Response must not have an assertion if it's an error response.",
                    node = node)
            }
        }
    }
}
