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
package org.codice.compliance.utils

import com.jayway.restassured.path.xml.element.Node
import com.jayway.restassured.response.Response
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
                it.children()
                        .list()
                        .any { formControl ->
                            SAML_RESPONSE.equals(formControl.getAttribute(NAME), ignoreCase = true)
                                || SAML_REQUEST.equals(formControl.getAttribute(NAME),
                                    ignoreCase = true)
                        }
            }
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

fun Node.hasNoAttributeWithNameAndValue(attributeName: String,
                                                expectedValue: String): Boolean {
    return expectedValue != this.getAttribute(attributeName)
}
