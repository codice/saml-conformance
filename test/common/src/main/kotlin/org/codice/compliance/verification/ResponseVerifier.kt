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

package org.codice.compliance.verification

import io.kotlintest.matchers.shouldNotBe
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLSpecRefMessage.*
import org.codice.compliance.saml.plugin.IdpPostResponse
import org.codice.compliance.saml.plugin.IdpRedirectResponse
import org.codice.compliance.saml.plugin.IdpResponse
import org.codice.compliance.utils.TestCommon.Companion.buildDom
import org.codice.compliance.verification.binding.BindingVerifier
import org.codice.compliance.verification.binding.PostVerifier
import org.codice.compliance.verification.binding.RedirectVerifier
import org.codice.security.sign.Decoder
import org.codice.security.sign.Decoder.InflationException
import org.codice.security.sign.Decoder.InflationException.InflErrorCode
import org.w3c.dom.Node
import java.io.IOException

sealed class ResponseVerifier(val response: IdpResponse) {

    internal fun verifyResponse(): Node {
        response.decodedSamlResponse = decodeResponse(response)
        response.responseDom = response.buildDom()
        getBindingVerifier(response).verifyBinding()

        return response.responseDom
    }

    protected abstract fun decodeResponse(response: IdpResponse): String
    protected abstract fun getBindingVerifier(response: IdpResponse): BindingVerifier

}

class RedirectResponseVerifier(response: IdpResponse) : ResponseVerifier(response) {

    override fun decodeResponse(response: IdpResponse): String {
        val samlResponse = response.samlResponse
        val samlEncoding = (response as IdpRedirectResponse).samlEncoding
        val decodedMessage: String

        /**
         * A query string parameter named SAMLEncoding is reserved to identify the encoding mechanism used. If this
         * parameter is omitted, then the value is assumed to be
         * urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE.
         */
        decodedMessage = if (samlEncoding == null ||
                samlEncoding.equals("urn:oasis:names:tc:SAML:2.0:bindings:URL-Encoding:DEFLATE")) {
            try {
                Decoder.decodeAndInflateRedirectMessage(samlResponse)
            } catch (e: InflationException) {
                when (e.inflErrorCode) {
                    InflErrorCode.ERROR_DECODING -> {
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_b1,
                                message = "Could not decode the SAML response.",
                                cause = e)
                    }
                    InflErrorCode.ERROR_INFLATING -> {
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a1,
                                message = "Could not inflate the SAML response.",
                                cause = e)
                    }
                    InflErrorCode.LINEFEED_OR_WHITESPACE -> {
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a2,
                                message = "There were linefeeds or whitespace in the SAML response.",
                                cause = e)
                    }
                    else -> {
                        throw SAMLComplianceException.create(SAMLBindings_3_4_4_1_a,
                                message = "Something went wrong with the SAML response.",
                                cause = e)
                    }
                }
            }
        } else throw UnsupportedOperationException("This test suite only supports DEFLATE encoding currently.")

        decodedMessage shouldNotBe null

        return decodedMessage
    }

    override fun getBindingVerifier(response: IdpResponse): BindingVerifier {
        return RedirectVerifier(response as IdpRedirectResponse)
    }
}

class PostResponseVerifier(response: IdpPostResponse) : ResponseVerifier(response) {

    override fun decodeResponse(response: IdpResponse): String {
        val samlResponse = response.samlResponse
        val decodedMessage: String
        try {
            decodedMessage = Decoder.decodePostMessage(samlResponse)
        } catch (exception: IOException) {
            throw SAMLComplianceException.create(SAMLBindings_3_5_4_a,
                    message = "The SAML response could not be decoded.",
                    cause = exception)
        }

        decodedMessage shouldNotBe null

        return decodedMessage
    }

    override fun getBindingVerifier(response: IdpResponse): BindingVerifier {
        return PostVerifier(response as IdpPostResponse)
    }
}

// todo once we support more bindings, Section 3.1.1: "if a SAML request message is accompanied by RelayState data,
// then the SAML responder MUST return its SAML protocol response using a binding that also supports a RelayState
// mechanism"
/**
 * Delegates the response to the correct POST or REDIRECT binding
 */
fun verifyResponse(response: IdpResponse): Node {
    return when (response) {
        is IdpRedirectResponse -> RedirectResponseVerifier(response).verifyResponse()
        is IdpPostResponse -> PostResponseVerifier(response).verifyResponse()
        else -> throw UnsupportedOperationException("This binding is not yet supported")
    }
}
