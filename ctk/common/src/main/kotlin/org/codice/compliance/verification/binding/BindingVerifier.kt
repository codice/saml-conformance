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

import org.codice.compliance.SAMLBindings_3_5_6_a
import org.codice.compliance.SAMLComplianceException

abstract class BindingVerifier {
    companion object {
        private const val HTTP_ERROR_THRESHOLD = 400
        /**
         * Verifies the http status code of the response is not an error status code
         * according to the binding spec
         * 3.4.6 & 3.5.6 Error Reporting
         */
        fun verifyHttpStatusCode(code: Int, message: String = "") {
            if (code >= HTTP_ERROR_THRESHOLD) {
                throw SAMLComplianceException.createWithPropertyMessage(
                        SAMLBindings_3_5_6_a,
                        property = "HTTP Status Code",
                        actual = code.toString(),
                        expected = "${message}A non-error http status code, i.e. less than " +
                                HTTP_ERROR_THRESHOLD
                )
            }
        }
    }

    abstract fun verifyError(extraMessage: String = "")
    abstract fun verify()
}
