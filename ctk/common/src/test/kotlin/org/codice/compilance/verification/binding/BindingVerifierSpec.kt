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
package org.codice.compilance.verification.binding

import io.kotlintest.forAll
import io.kotlintest.shouldThrow
import io.kotlintest.specs.StringSpec
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.verification.binding.BindingVerifier
import java.net.HttpURLConnection

@Suppress("MagicNumber")
class BindingVerifierSpec : StringSpec() {
    init {
        var startCode = 100

        val codeSeq = generateSequence { (startCode++).takeIf { it < 600 } }
                .toList()

        "Check Status Code is not Error" {
            forAll(codeSeq) { code ->
                if (code >= HttpURLConnection.HTTP_BAD_REQUEST) {
                    shouldThrow<SAMLComplianceException> {
                        BindingVerifier.verifyHttpStatusCode(code)
                    }
                } else {
                    BindingVerifier.verifyHttpStatusCode(code)
                }
            }
        }

        "Check Error Status Code is not Error" {
            forAll(codeSeq) { code ->
                if (code >= HttpURLConnection.HTTP_BAD_REQUEST) {
                    shouldThrow<SAMLComplianceException> {
                        BindingVerifier.verifyHttpStatusCode(code)
                    }
                } else {
                    BindingVerifier.verifyHttpStatusCode(code)
                }
            }
        }
    }
}
