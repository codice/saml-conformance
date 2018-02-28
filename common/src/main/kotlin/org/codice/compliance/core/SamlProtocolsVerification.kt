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
package org.codice.compliance.core

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.allChildren
import org.codice.compliance.children
import org.w3c.dom.Node

/**
 * Verify protocols against the Core Spec document
 * 3 SAML Protocols
 */
fun verifyProtocols(node: Node) {
    verifyArtifactResolutionProtocol(node)
    verifyNameIdentifierMappingProtocol(node)
}



/**
 * Verify the Artifact Resolution Protocol
 * 3.5.1 Element <ArtifactResolve>
 */
fun verifyArtifactResolutionProtocol(node: Node) {
    // ArtifactResolve
    val artifactResolves = node.allChildren("ArtifactResolve")
    artifactResolves.forEach {
        if (it.children("Artifact").isEmpty())
            throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.5.1", "Artifact", "ArtifactResolve")
    }

    // todo - test for processing rules (potential separate from this) SAMLCore.3.5.3 Processing Rules
}

/**
 * Verify the Name Identifier Mapping Protocol
 * 3.8.2 Element <NameIDMappingResponse>
 */
fun verifyNameIdentifierMappingProtocol(node: Node) {
    val nameIdMappingResponse = node.allChildren("NameIDMappingResponse")
    nameIdMappingResponse.forEach {
        if (it.children("NameID").isEmpty() && it.children("EncryptedID").isEmpty())
            throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.6.1", "NameID or EncryptedID", "NameIDMappingResponse")
    }
}