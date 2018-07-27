/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
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
