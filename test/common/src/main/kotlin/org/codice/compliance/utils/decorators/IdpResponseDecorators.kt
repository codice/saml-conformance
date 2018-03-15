package org.codice.compliance.utils.decorators

import org.codice.compliance.saml.plugin.IdpPostResponse
import org.codice.compliance.saml.plugin.IdpRedirectResponse
import org.w3c.dom.Node
import javax.xml.parsers.DocumentBuilderFactory

interface IdpResponseDecorator {

    var isRelayStateGiven: Boolean
    var decodedSamlResponse: String?
    var responseDom: Node?


    fun buildDom() {
        responseDom = DocumentBuilderFactory.newInstance().apply {
            isNamespaceAware = true
        }.newDocumentBuilder()
                .parse(decodedSamlResponse?.byteInputStream())
                .documentElement
    }
}

class IdpResponseDecoratorFactory {
    companion object {
        fun getDecorator(response: IdpRedirectResponse): IdpRedirectResponseDecorator {
            return IdpRedirectResponseDecorator(response)
        }

        fun getDecorator(response: IdpPostResponse): IdpPostResponseDecorator {
            return IdpPostResponseDecorator(response)
        }
    }
}


class IdpRedirectResponseDecorator(response: IdpRedirectResponse) : IdpRedirectResponse(response), IdpResponseDecorator {

    override var isRelayStateGiven: Boolean = false
    override var decodedSamlResponse: String? = null
        set(value) {
            field = value
            buildDom()
        }
    override var responseDom: Node? = null
}

class IdpPostResponseDecorator(response: IdpPostResponse) : IdpPostResponse(response), IdpResponseDecorator {
    override var isRelayStateGiven: Boolean = false
    override var decodedSamlResponse: String? = null
        set(value) {
            field = value
            buildDom()
        }
    override var responseDom: Node? = null
}