/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
@file:Suppress("TooManyFunctions")

package org.codice.compliance.utils

import io.restassured.path.xml.element.Node
import io.restassured.response.Response
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_REQUEST
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.binding.PostBindingVerifier
import org.codice.compliance.verification.binding.RedirectBindingVerifier
import org.codice.security.saml.SamlProtocol

/** Response extension functions **/
private const val BINDING_UNSUPPORTED_MESSAGE = "Binding is not currently supported."

fun Response.determineBinding(): SamlProtocol.Binding {
    return with(this) {
        when {
            isPostBinding() -> SamlProtocol.Binding.HTTP_POST
            isRedirectBinding() -> SamlProtocol.Binding.HTTP_REDIRECT
            else -> throw UnsupportedOperationException(BINDING_UNSUPPORTED_MESSAGE)
        }
    }
}

fun Response.getBindingVerifier(): BindingVerifier {
    // checking the status code of the response before attempting to determine the binding
    // because the binding cannot be determined from an http error response
    BindingVerifier.verifyHttpStatusCode(this.statusCode)

    return when (this.determineBinding()) {
        SamlProtocol.Binding.HTTP_REDIRECT -> RedirectBindingVerifier(this)
        SamlProtocol.Binding.HTTP_POST -> PostBindingVerifier(this)
        else -> throw UnsupportedOperationException(BINDING_UNSUPPORTED_MESSAGE)
    }
}

fun Response.getLocation(): String? {
    return when (this.determineBinding()) {
        SamlProtocol.Binding.HTTP_REDIRECT -> {
            // Extracted according to Binding 3.4.4
            this.getHeader(LOCATION)
        }
        SamlProtocol.Binding.HTTP_POST -> {
            // Extracted according to Bindings 3.5.4
            this.extractSamlMessageForm()?.getAttribute(ACTION)
        }
        else -> throw UnsupportedOperationException(BINDING_UNSUPPORTED_MESSAGE)
    }
}

fun Response.extractSamlMessageForm(): Node? {
    return this
            .then()
            .extract()
            .htmlPath()
            .getList("**.find { it.name() == 'form' }", Node::class.java)
            .firstOrNull {
                it.recursiveChildren("input")
                        .any { formControl ->
                            SAML_RESPONSE.equals(formControl.getAttribute(NAME), ignoreCase = true) ||
                                SAML_REQUEST.equals(formControl.getAttribute(NAME),
                                    ignoreCase = true)
                        }
            }
}

private fun Node.childrenSearch(name: String? = null): List<Node> {
    val predicate: (Node) -> Boolean =
            if (name == null) {
                { true }
            } else {
                { it.name() == name }
            }

    return ((this.children().size() - 1) downTo 0)
            .map { this.children().get(it) }
            .filter(predicate)
            .toList()
}

/**
 * Finds all of the children of a {@code Node}, regardless of how deep an element is nested in its
 * children.
 *
 * @param name - Optional element name to match.
 * @return List of child {@code Nodes}.
 */
fun Node.recursiveChildren(name: String? = null): List<Node> {
    val nodes = mutableListOf<Node>()
    this.childrenSearch().forEach {
        if (name == null || name == it.name()) nodes.add(it)
        nodes.addAll(it.recursiveChildren(name))
    }
    return nodes
}

private fun Response.isPostBinding(): Boolean {
    return this.extractSamlMessageForm() != null
}

private fun Response.isRedirectBinding(): Boolean {
    return this.getHeader(LOCATION)?.contains("$SAML_RESPONSE=") == true ||
        this.getHeader(LOCATION)?.contains("$SAML_REQUEST=") == true
}

/** Node extension functions **/

fun Node.extractValue(): String? {
    if (!this.value().isNullOrEmpty()) {
        return this.value()
    }

    return if (!this.attributes()?.get(VALUE).isNullOrEmpty()) {
        this.attributes()?.get(VALUE)
    } else null
}

fun Node.isNotHidden(): Boolean {
    return !HIDDEN.equals(this.getAttribute(TYPE_LOWER), ignoreCase = true)
}

fun Node.hasNoAttributeWithNameAndValue(
    attributeName: String,
    expectedValue: String
): Boolean {
    return expectedValue != this.getAttribute(attributeName)
}
