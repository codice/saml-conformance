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

const val XSI = "http://www.w3.org/2001/XMLSchema-instance"
const val ELEMENT = "http://www.w3.org/2001/04/xmlenc#Element"

const val ASSERTION_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:assertion"
const val PROTOCOL_NAMESPACE = "urn:oasis:names:tc:SAML:2.0:protocol"
const val ENTITY = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
const val BEARER = "urn:oasis:names:tc:SAML:2.0:cm:bearer"
const val HOLDER_OF_KEY_URI = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"

const val ENCRYPTED_ID = "urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted"
const val PERSISTENT_ID = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
const val TRANSIENT_ID = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient"

const val PASSWORD_AUTH = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
const val PASS_PROTECTED_TRANSPORT =
        "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
const val X509_AUTH = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
const val SMART_CARD_PKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"
const val SOFTWARE_PKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SoftwarePKI"
const val SPKI_AUTH = "urn:oasis:names:tc:SAML:2.0:ac:classes:SPKI"
const val TLS_CLIENT = "urn:oasis:names:tc:SAML:2.0:ac:classes:TLSClient"
val ddfAuthnContextList = setOf(PASSWORD_AUTH, PASS_PROTECTED_TRANSPORT, X509_AUTH, SMART_CARD_PKI,
        SOFTWARE_PKI, SPKI_AUTH, TLS_CLIENT)

const val ID = "ID"
const val ASSERTION = "Assertion"
const val RESPONSE = "Response"
const val LOGOUT_RESPONSE = "LogoutResponse"
const val LOGOUT_REQUEST = "LogoutRequest"
const val TYPE = "Type"
const val METHOD = "Method"
const val FORMAT = "Format"
const val SUBJECT = "Subject"
const val VERSION = "Version"
const val DESTINATION = "Destination"
const val CONSENT = "Consent"
const val STATUS = "Status"
const val STATUS_CODE = "StatusCode"
const val AUDIENCE = "Audience"
const val BASE_ID = "BaseID"
const val NAME_ID = "NameID"
const val SUBJECT_CONFIRMATION = "SubjectConfirmation"
const val SUBJECT_CONFIRMATION_DATA = "SubjectConfirmationData"
const val KEY_INFO_CONFIRMATION_DATA_TYPE = "KeyInfoConfirmationDataType"
const val AUTHN_STATEMENT = "AuthnStatement"
const val NAME = "name"
const val VALUE = "value"
const val HIDDEN = "hidden"
const val TYPE_LOWER = "type"
const val ACTION = "action"
const val LOCATION = "Location"
const val SAML_ENCODING = "SAMLEncoding"
const val SP_NAME_QUALIFIER = "SPNameQualifier"

const val EXAMPLE_RELAY_STATE = "relay+State"
const val RELAY_STATE_GREATER_THAN_80_BYTES = "RelayStateLongerThan80CharsIsIncorrect" +
        "AccordingToTheSamlSpecItMustNotExceed80BytesInLength"
const val MAX_RELAY_STATE_LEN = 80
const val INCORRECT_DESTINATION = "https://incorrect.destination.com"

const val SUCCESS = "urn:oasis:names:tc:SAML:2.0:status:Success"
const val REQUESTER = "urn:oasis:names:tc:SAML:2.0:status:Requester"
const val RESPONDER = "urn:oasis:names:tc:SAML:2.0:status:Responder"
const val PARTIAL_LOGOUT = "urn:oasis:names:tc:SAML:2.0:status:PartialLogout"
private const val VERSION_MISMATCH = "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"
val topLevelStatusCodes = setOf(SUCCESS, REQUESTER, RESPONDER, VERSION_MISMATCH)

const val KEYSTORE_PASSWORD = "org.apache.ws.security.crypto.merlin.keystore.password"
const val PRIVATE_KEY_ALIAS = "org.apache.ws.security.crypto.merlin.keystore.alias"
const val PRIVATE_KEY_PASSWORD =
        "org.apache.ws.security.crypto.merlin.keystore.private.password"
