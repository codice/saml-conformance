package org.codice.compliance.verification.binding

abstract class BindingVerifier {
    companion object {
        const val MAX_RELAYSTATE_LEN = 80
    }

    abstract fun verifyBinding()
}
