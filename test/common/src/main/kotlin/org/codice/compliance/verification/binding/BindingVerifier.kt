package org.codice.compliance.verification.binding

import org.w3c.dom.Node

abstract class BindingVerifier(val responseDom: Node, val parsedResponse: Map<String, String>, val givenRelayState: Boolean) {
    abstract fun verifyBinding()
}