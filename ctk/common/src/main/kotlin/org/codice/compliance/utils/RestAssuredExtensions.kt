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
private const val EMPTY_BODY_MESSAGE =
        "The binding in use is not Redirect and the response body is empty."

/**
 * Determines the {@code Response} binding.
 *
 * @return the {@code SamlProtocol.Binding} representation of the {@code Response} binding
 * @throws IllegalArgumentException if the bindings is not redirect and the {@code Response}
 * has an empty body
 * @throws UnsupportedOperationException if the binding cannot be determined
 */
fun Response.determineBinding(): SamlProtocol.Binding {
    return with(this) {
        when {
            isRedirectBinding() -> SamlProtocol.Binding.HTTP_REDIRECT
            // Verify that the body is not empty
            body.asString().isBlank() -> throw IllegalArgumentException(EMPTY_BODY_MESSAGE)
            isPostBinding() -> SamlProtocol.Binding.HTTP_POST
            else -> throw UnsupportedOperationException(BINDING_UNSUPPORTED_MESSAGE)
        }
    }
}

/**
 * Verifies that the {@code Response} is not an error response and finds the {@code BindingVerifier}
 * that matches the {@code Response} binding.
 *
 * @return the verifier which corresponds to the response's binding.
 */
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

/**
 * Finds the assertion consumer service url of the SAML Request or Response
 *
 * @return the assertion consumer service url
 */
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

/**
 * Extracts the SAMLRequest or SAMLResponse from the given {@code Response} body
 *
 * @return the {@code Node} containing the SAMLRequest or SAMLResponse
 */
fun Response.extractSamlMessageForm(): Node? {
    return this
            .then()
            .extract()
            .htmlPath()
            .getList("**.find { it.name() == 'form' }", Node::class.java)
            .firstOrNull {
                it.recursiveChildren("input")
                        .any { formControl ->
                            SAML_RESPONSE.equals(formControl.getAttribute(NAME),
                                    ignoreCase = true) ||
                                    SAML_REQUEST.equals(formControl.getAttribute(NAME),
                                            ignoreCase = true)
                        }
            }
}

/**
 * Finds the immediate children of a {@code Node}.
 *
 * @param name - Optional element name to match.
 * @return List of child {@code Nodes}.
 */
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

/**
 * @return true if the SAML message was successfully extracted or false otherwise
 */
private fun Response.isPostBinding(): Boolean {
    return this.extractSamlMessageForm() != null
}

/**
 * @return true if the Location header conatins a SAMLRequest or a SAMLResponse
 */
private fun Response.isRedirectBinding(): Boolean {
    return this.getHeader(LOCATION)?.contains("$SAML_RESPONSE=") == true ||
            this.getHeader(LOCATION)?.contains("$SAML_REQUEST=") == true
}

/** Node extension functions **/

/**
 * @return the value of the given {@code Node}
 */
fun Node.extractValue(): String? {
    if (!this.value().isNullOrEmpty()) {
        return this.value()
    }

    return if (!this.attributes()?.get(VALUE).isNullOrEmpty()) {
        this.attributes()?.get(VALUE)
    } else null
}

/**
 * @return true if the {@code Node}'s type is hidden or false otherwise
 */
fun Node.isNotHidden(): Boolean {
    return !HIDDEN.equals(this.getAttribute(TYPE_LOWER), ignoreCase = true)
}

/**
 * @return true if the {@code Node} doesn't have an attribute matching the given name and value or
 * false if it does.
 */
fun Node.hasNoAttributeWithNameAndValue(
    attributeName: String,
    expectedValue: String
): Boolean {
    return expectedValue != this.getAttribute(attributeName)
}
