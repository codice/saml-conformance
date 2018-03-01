package org.codice.compliance.core

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.children
import org.w3c.dom.Node

/**
 * Verify Logout Request Protocol against the Core document
 * 3.7.1 Element <LogoutRequest>
 */
fun verifyLogoutRequestProtocol(request: Node) {
    request.children("LogoutRequest").forEach {
        if(it.attributes.getNamedItem("Reason") != null)
            verifyUriValues(it.attributes.getNamedItem("Reason"), "SAMLCore.3.7.1_a")

        if(it.children("BaseID").isEmpty()
                && it.children("NameID").isEmpty()
                && it.children("EncryptedID").isEmpty())
            throw SAMLComplianceException.createWithReqMessage("SAMLCore.3.7.1", "BaseID or NameID or EncryptedID", "LogoutRequest")

    }
}