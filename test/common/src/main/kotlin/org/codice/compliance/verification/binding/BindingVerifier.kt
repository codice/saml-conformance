package org.codice.compliance.verification.binding

import org.codice.compliance.saml.plugin.IdpResponse
import org.w3c.dom.Node

abstract class BindingVerifier {
    abstract fun verifyBinding()
}