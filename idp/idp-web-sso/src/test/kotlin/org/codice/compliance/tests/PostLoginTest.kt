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
package org.codice.compliance.tests

import com.jayway.restassured.RestAssured
import com.jayway.restassured.RestAssured.given
import io.kotlintest.matchers.shouldBe
import io.kotlintest.matchers.shouldNotBe
import io.kotlintest.specs.StringSpec
import org.apache.cxf.helpers.DOMUtils
import org.apache.cxf.rs.security.saml.sso.SamlpRequestComponentBuilder
import org.apache.wss4j.common.saml.builder.SAML2Constants
import org.codice.compliance.assertions.*
import org.codice.security.saml.SamlProtocol
import org.codice.security.sign.Decoder
import org.codice.security.sign.Encoder
import org.codice.security.sign.SimpleSign
import org.joda.time.DateTime
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport
import org.opensaml.saml.common.SAMLObjectBuilder
import org.opensaml.saml.common.SAMLVersion
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.core.Issuer
import org.w3c.dom.Document
import java.nio.charset.StandardCharsets
import javax.xml.parsers.DocumentBuilderFactory
import org.apache.wss4j.common.util.DOM2Writer
import org.apache.wss4j.common.saml.OpenSAMLUtil
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder
import org.opensaml.saml.saml2.core.impl.IssuerBuilder
import org.opensaml.saml.saml2.core.impl.NameIDPolicyBuilder
import java.net.URLEncoder


//val authnRequestBuilder = XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME) as SAMLObjectBuilder<AuthnRequest>
//val issuerBuilder = XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME) as SAMLObjectBuilder<Issuer>


class PostLoginTest : StringSpec({

    RestAssured.useRelaxedHTTPSValidation()

    "POST AuthnRequest Test" {
        val authnRequest = generateAndRetrieveAuthnRequest()
        val encodedRequest = Encoder.encodePostMessage(authnRequest)
        val response = given()
                .urlEncodingEnabled(false)
                .body(encodedRequest)
                .contentType("application/x-www-form-urlencoded")
                .log()
                .ifValidationFails()
                .`when`()
                .post("https://localhost:8993/services/idp/login")

        response.statusCode shouldBe 200
//        val idpResponse = getIdpResponse(queryParams)
//        assertPostResponse(idpResponse)
    }
})

fun generateAndRetrieveAuthnRequest(): String {

    OpenSAMLUtil.initSamlEngine()

    val issuerObject = IssuerBuilder().buildObject().apply {
        value = SP_ISSUER
    }

    val authnRequest = AuthnRequestBuilder().buildObject().apply {
        issuer = issuerObject
        assertionConsumerServiceURL = ACS
        id = ID
        version = SAMLVersion.VERSION_20
        issueInstant = DateTime()
        destination = DESTINATION
        protocolBinding = SamlProtocol.POST_BINDING
        nameIDPolicy = NameIDPolicyBuilder().buildObject().apply {
            allowCreate = true
            format = SAML2Constants.NAMEID_FORMAT_PERSISTENT
            spNameQualifier = SP_ISSUER
        }
    }

    SimpleSign().signSamlObject(authnRequest)

    val doc = DOMUtils.createDocument()
    doc.appendChild(doc.createElement("root"))

    val requestElement = OpenSAMLUtil.toDom(authnRequest, doc)

    return DOM2Writer.nodeToString(requestElement)
}

fun assertPostResponse(samlResponse: String) {
    val decodedMessage = Decoder.decodeRedirectMessage(samlResponse)
    decodedMessage shouldNotBe null

    val docBuilder: DocumentBuilderFactory = DocumentBuilderFactory.newInstance()
    docBuilder.isNamespaceAware = true
    val xmlDoc: Document = docBuilder.newDocumentBuilder().parse(decodedMessage.byteInputStream())
    val responseElement = xmlDoc.documentElement

    // Get response Assertions.children elements
    val status = responseElement.children("Status")
    val assertion = responseElement.children("Assertion")

    // CHECK ISSUER
    checkIssuer(responseElement)

    //CHECK ASSERTION
    checkAssertions(assertion)
}
