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
package org.codice.compliance.assertions

import com.google.common.io.Resources.getResource
import org.codice.security.saml.IdpMetadata
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport
import org.opensaml.saml.common.SAMLObjectBuilder
import org.opensaml.saml.saml2.core.AuthnRequest
import org.opensaml.saml.saml2.metadata.IDPSSODescriptor
import org.w3c.dom.Node

const val SP_ISSUER = "https://localhost:8993/services/saml"
const val DESTINATION = "https://localhost:8993/services/idp/login"
const val ACS = "https://localhost:8993/services/saml/sso"
const val ID = "a1chfeh0234hbifc1jjd3cb40ji0d49"
val IDP_METADATA = getIdpMetadata()

class SAMLComplianceException(override var message: String) : Exception(message)

/**
 * Parses and returns the idp metadata
 */
fun getIdpMetadata() : IDPSSODescriptor? {
    val idpMetadataParser = IdpMetadata()
    idpMetadataParser.setMetadata(getResource("idp-metadata.xml").path)
    return idpMetadataParser.descriptor
}

/**
 * Extension to Node class.
 *
 * @param name - Name of Assertions.children
 * @return list of Assertions.children matching the name provided
 */
fun Node.children(name : String): List<Node> {
    val childNodes = mutableListOf<Node>()
    var i = this.childNodes.length - 1
    while (i >= 0){
        val child = this.childNodes.item(i)
        if(child.localName == name)
            childNodes.add(child); i -= 1
    }
    return childNodes
}