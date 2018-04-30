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
import org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE
import org.codice.compliance.utils.TestCommon.Companion.NAME
import org.codice.security.saml.SamlProtocol

fun Response.determineBinding(): SamlProtocol.Binding {
    return with(this) {
        when {
            isPostBinding() -> SamlProtocol.Binding.HTTP_POST
            isRedirectBinding() -> SamlProtocol.Binding.HTTP_REDIRECT
            else -> throw UnsupportedOperationException("Binding is not currently supported.")
        }
    }
}

fun Response.extractSamlResponseForm(): Node? {
    return this
            .then()
            .extract()
            .htmlPath()
            .getList("**.find { it.name() == 'form' }", Node::class.java)
            .filter {
                it.children()
                        .list()
                        .stream()
                        .anyMatch { formControl ->
                            SAML_RESPONSE.equals(formControl.getAttribute(NAME),
                                    ignoreCase = true)
                        }
            }.firstOrNull()
}

private fun Response.isPostBinding(): Boolean {
    return this.extractSamlResponseForm() != null
}

private fun Response.isRedirectBinding(): Boolean {
    return this.getHeader("Location")?.contains("$SAML_RESPONSE=") == true
}
