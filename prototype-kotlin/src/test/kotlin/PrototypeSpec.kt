import com.jayway.restassured.RestAssured
import org.jetbrains.spek.api.Spek
import org.jetbrains.spek.api.dsl.describe
import org.jetbrains.spek.api.dsl.on
import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.util.*
import java.util.zip.Deflater
import java.util.zip.DeflaterOutputStream
import com.jayway.restassured.RestAssured.given
import org.jetbrains.spek.api.dsl.it
import org.jetbrains.spek.api.dsl.xon
import java.net.URLEncoder
import kotlin.test.assertEquals

/**
 * Copyright (c) Codice Foundation
 * <p>
 * This is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser
 * General Public License as published by the Free Software Foundation, either version 3 of the
 * License, or any later version.
 * <p>
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details. A copy of the GNU Lesser General Public License
 * is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */

// Actual test case
object PrototypeSpec : Spek({
    describe("REST") {
        RestAssured.useRelaxedHTTPSValidation()

        // xon means ignore the test
        on("Spring-Security login") {
            val samlRequest = "nVLLbsIwEPwVa%2B8hD4IULEJFW1VFalXUhB56c5wtGCV26nVQ%2B%2Fc1AVR64dCLpdXuzszOeHbz1TZsj5aU0TnEowgYamlqpTc5rMuHIIOb%2BYxE2yQdX%2FRuq1%2Fxs0dyzC9q4sdODr3V3AhSxLVokbiTvFg8P%2FFkFPHOGmekaYAtiNA6T3VnNPUt2gLtXklcvz7lsHWu42FYe3BRjRojRcOzKKTOejEBoeytct%2FBwHh4uwbDQxEWxQuwe7%2BmtHDDHQco8lgDyNaQ49l0Og7pyEahqjvf2ygN7MFYicNhOXyIhhDY8j4HkWbpdJLEarKRk2qXprvko6p3KWbZRFZ%2BhlaCSO3xd4uox6X24rXLIYniLIiSIE7KeMrHMY%2FT0ThK3oGtTm7cKn10%2BZp11XGI%2BGNZroLVS1ECezun5QfglA0f2O1lKNeBxTkJmP%2Fb9xadqIUTs%2FBSw%2FxU%2Fv0u8x8%3D"
            val idpResponse = given()
                    .urlEncodingEnabled(false)
                    .param("SAMLRequest", samlRequest)
//                    .param("RelayState", "relaystate")
                    .param("SigAlg",
                            "http%3A%2F%2Fwww.w3.org%2F2000%2F09%2Fxmldsig%23rsa-sha1")
                    .param("Signature",
                            "WVsLgknj9%2BToIdvKFvgnftEr3N2ePhviNNRBqiK8ayhZOozlWhilmm%2FNAWASUOjvFDPGDI74kFSq0Qnz8j3beu3cakhAKUYCj2aJx3PnoCPwq84BTNu7O5MgBnBxgEJ9hDJEaDoD4yUXHNnZHX%2BEJF9b3aWOLm%2BhnblKTixm4HQWJQO0yr%2FLvrkQD3ct21vPnK5HL46l2vuMFNrSmN2A%2BGI9b5C%2FZFt%2FXXlm53dowXvModHj4F5X1boh1arx1%2FvwMOD%2FL4ZW%2FnzQRPHzJuQi9iWqaqpi%2FHLHkJhgm6MeIOHTz%2BUjAroScr52xMpl5F8bRrAomV1BGbjwltwA%2BQSDJw%3D%3D")
                    .contentType("application/x-www-form-urlencoded")
                    .log()
                    .ifValidationFails()
                    .`when`()
                    .get("https://localhost:8993/services/idp/login")
            it("should return 200 status code") {
                System.out.println("SPRING-SECURITY ITasdfs")
                assertEquals(200, idpResponse.statusCode())

            }
        }


        xon("DDF login") {
            val idpResponse = given()
                    .auth()
                    .preemptive()
                    .basic("admin", "admin")
                    .param("AuthMethod", "up")
                    .param("SAMLRequest", getEncodedSamlRequest("example-ddf-saml-request.xml"))
                    .param("RelayState", "relaystate")
                    .param("SigAlg",
                            "http://www.w3.org/2000/09/xmldsig#rsa-sha1")
                    .param("Signature",
                            "sCch7vE1n7976r19DPNXGA7hVfzG14PAtgfKVi2uN06B11jf7il55UuZZZqlv2lfQJiGXcEVynmYWcG5FFcKCmTIRFxEkOxwC5zhbqgD2CcXS3tGvK4gafU7zliJu/27FY2x2L2hVo0j+Xv+MHp/p/OXE4qVvWyQWG02jcYRY62Ry6z8NOO5OHikDYZb4seZizoLYPrr6ImsJNBU2ZFLi7/8wUqpDBP6jjYDPqa8v6gRyQ72iA4LvZkaTGai/ieOz5RSqaES137pcanrClo2A0gdVAYSxewPAkO/i/SuyAR8x0UcFTEIo2mkdIlnK7mAPFZGVJA+OaS3dPWLgzCznQ==")
                    .param(
                            "OriginalBinding",
                            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect")
                    .`when`()
                    .get("https://localhost:8993/services/idp/login/sso")
            it("should return 200 status code") {
                System.out.println("DDF IT")
                assertEquals(200, idpResponse.statusCode())
            }
        }
    }
})

// "top-level" functions. i.e. Associated with the file instead of the class.
// private means only accessible within the file
private fun getEncodedSamlRequest(fileName: String): String {
    val valueBytes = ByteArrayOutputStream()
    DeflaterOutputStream(valueBytes, Deflater(Deflater.DEFLATED, true)).use { tokenStream ->
        val fileContent = PrototypeSpec::class.java.getResource(fileName).readText()
        tokenStream.write(fileContent.toByteArray(StandardCharsets.UTF_8))
        tokenStream.close()

        return Base64.getEncoder().encodeToString(valueBytes.toByteArray())
    }
}