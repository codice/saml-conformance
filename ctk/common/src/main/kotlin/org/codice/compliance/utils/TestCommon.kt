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

import com.jayway.restassured.response.Response
import org.apache.cxf.helpers.DOMUtils
import org.apache.wss4j.common.saml.OpenSAMLUtil
import org.apache.wss4j.common.util.DOM2Writer
import org.codice.compliance.Common
import org.codice.compliance.IMPLEMENTATION_PATH
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.saml.plugin.IdpPostResponse
import org.codice.compliance.saml.plugin.IdpRedirectResponse
import org.codice.compliance.utils.decorators.IdpResponseDecorator
import org.codice.compliance.utils.decorators.decorate
import org.codice.security.saml.SamlProtocol
import org.opensaml.saml.saml2.core.AuthnRequest
import java.io.File
import java.net.URLClassLoader
import java.util.ServiceLoader
import kotlin.reflect.KClass

class TestCommon {
    companion object {
        const val XSI = "http://www.w3.org/2001/XMLSchema-instance"
        const val ELEMENT = "http://www.w3.org/2001/04/xmlenc#Element"
        const val SAML_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion"
        const val HOLDER_OF_KEY_URI = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"
        const val ID = "a1chfeh0234hbifc1jjd3cb40ji0d49"
        const val EXAMPLE_RELAY_STATE = "relay+State"
        const val RELAY_STATE_GREATER_THAN_80_BYTES = "RelayStateLongerThan80CharsIsIncorrect" +
                "AccordingToTheSamlSpecItMustNotExceed80BytesInLength"
        const val MAX_RELAYSTATE_LEN = 80

        const val IDP_ERROR_RESPONSE_REMINDER_MESSAGE = "Make sure the IdP responds immediately " +
                "with a correctly formatted SAML error response (See section 3.2.1 in the SAML " +
                "Core specification)"
        const val REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester"
        const val VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
        private const val SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
        private const val RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder"
        val TOP_LEVEL_STATUS_CODES = setOf(SUCCESS, REQUESTER, RESPONDER, VERSION_MISMATCH)

        private val DEPLOY_CL = getDeployDirClassloader()
        private val spMetadata = Common.parseSpMetadata()

        val idpMetadata = Common.parseIdpMetadata()
        val SP_ISSUER = spMetadata.keys.first()

        val acsUrl: Map<SamlProtocol.Binding, String?> by lazy {
            val spInfo = spMetadata[SP_ISSUER]
            if (spInfo == null) {
                emptyMap()
            } else {
                SamlProtocol.Binding.values()
                        .associate {
                            it to spInfo.getAssertionConsumerService(it)?.url
                        }
            }
        }

        /**
         * Converts the {@param authnRequest} to a String
         */
        fun authnRequestToString(authnRequest: AuthnRequest): String {
            val doc = DOMUtils.createDocument().apply {
                appendChild(createElement("root"))
            }

            val requestElement = OpenSAMLUtil.toDom(authnRequest, doc)
            return DOM2Writer.nodeToString(requestElement)
        }

        fun <T : Any> getServiceProvider(type: KClass<T>): T {
            return ServiceLoader.load(type.java, DEPLOY_CL).first()
        }

        private fun getDeployDirClassloader(): ClassLoader {
            val pluginDeploy = System.getProperty(IMPLEMENTATION_PATH)
            requireNotNull(pluginDeploy) {
                "Value required for System property $IMPLEMENTATION_PATH."
            }

            val walkTopDown = File(pluginDeploy).canonicalFile.walkTopDown()
            val jarUrls = walkTopDown.maxDepth(1)
                    .filter { it.name.endsWith(".jar") }
                    .map { it.toURI() }
                    .map { it.toURL() }
                    .toList()

            check(jarUrls.isNotEmpty()) {
                "No plugins found in $IMPLEMENTATION_PATH; CTK can not operate."
            }
            return URLClassLoader(jarUrls.toTypedArray(),
                    SAMLComplianceException::class.java.classLoader)
        }

        /*
         * Since errors shouldn't be passed to user implementations, this acts as the "user
         * implementation" and parses the response into the correct idp object for further
         * processing.
         *
         * @param response The error response returned from the first interaction with the IdP under
          * test.
         * @return An {@code IdpResponse} object created from the error response.
         */
        fun parseErrorResponse(response: Response): IdpResponseDecorator {
            return if (response.header("LOCATION") != null) {
                /*
                 * TODO "Manually change DDF IdP to respond with 302/303 status code for Redirect"
                 * Change this line to:
                 IdpRedirectResponse(response)
                 *
                 * And delete parseRedirectErrorResponse method when finished with ticket
                 */
                parseRedirectErrorResponse(response).decorate()
            } else {
                IdpPostResponse(response).decorate()
            }
        }

        private fun parseRedirectErrorResponse(response: Response): IdpRedirectResponse {
            return IdpRedirectResponse.Builder().apply {
                httpStatusCode(response.statusCode)
                url(response.header("LOCATION"))
            }.build()
        }
    }
}
