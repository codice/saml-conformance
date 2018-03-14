package org.codice.compliance.verification.core

import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLSpecRefMessage.SAMLCore_3_7_1
import org.codice.compliance.children
import org.w3c.dom.Node

class LogoutRequestProtocolVerifier(val request: Node) {
    /**
     * Verify Logout Request Protocol against the Core document
     * 3.7.1 Element <LogoutRequest>
     */
    fun verifyLogoutRequestProtocol() {
        request.children("LogoutRequest").forEach {
            if (it.attributes.getNamedItem("Reason") != null)
                verifyUriValues(it.attributes.getNamedItem("Reason"), SAMLCore_3_7_1)

            if (it.children("BaseID").isEmpty()
                    && it.children("NameID").isEmpty()
                    && it.children("EncryptedID").isEmpty())
                throw SAMLComplianceException.createWithPropertyReqMessage("SAMLCore.3.7.1", "BaseID or NameID or EncryptedID", "LogoutRequest")

        }
    }
}