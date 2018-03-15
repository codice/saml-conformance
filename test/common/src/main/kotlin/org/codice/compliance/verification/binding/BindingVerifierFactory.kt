package org.codice.compliance.verification.binding

import org.codice.compliance.utils.decorators.IdpPostResponseDecorator
import org.codice.compliance.utils.decorators.IdpRedirectResponseDecorator

class BindingVerifierFactory {
    companion object {
        fun getBindingVerifier(response: IdpRedirectResponseDecorator): RedirectBindingVerifier {
            return RedirectBindingVerifier(response)
        }
        fun getBindingVerifier(response: IdpPostResponseDecorator): PostBindingVerifier {
            return PostBindingVerifier(response)
        }
    }
}