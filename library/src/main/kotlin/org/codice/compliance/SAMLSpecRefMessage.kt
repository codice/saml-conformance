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
package org.codice.compliance

/**
 * It was decided to store these messages in an enum instead of a properties file for a few reasons:
 *  - From a developer perspective, it is easier to find usages of an enum than it is to find a String literal
 *  - The usage of enums is less error-prone than String literals
 *  - There is no need to have this list be as dynamic as a properties file at runtime
 */
@Suppress("StringLiteralDuplication")
enum class SAMLSpecRefMessage(val message: String) {
    /***************
     *
     * PROFILES
     *
     ***************/

    SAMLProfiles_3_1_a("""One or more <ds:KeyInfo> elements MUST be present within the <SubjectConfirmationData> """ +
            """element."""),

    SAMLProfiles_3_1_b("""An xsi:type attribute MAY be present in the <SubjectConfirmationData> element and, """ +
            """if present, MUST be set to saml:KeyInfoConfirmationDataType (the namespace prefix is arbitrary """ +
            """but must reference the SAML assertion namespace)."""),

    SAMLProfiles_3_1_c("""Note that in accordance with [XMLSig], each <ds:KeyInfo> element MUST identify a single """ +
            """cryptographic key. Multiple keys MAY be identified with separate <ds:KeyInfo> elements, such as when """ +
            """different confirmation keys are needed for different relying parties."""),

    SAMLProfiles_4_1_4_2_a("""If the <Response> message is signed or if an enclosed assertion is encrypted, then the """ +
            """<Issuer> element MUST be present."""),

    SAMLProfiles_4_1_4_2_b("""If present [the Issuer] MUST contain the unique identifier of the issuing identity """ +
            """provider."""),

    SAMLProfiles_4_1_4_2_c("""The Format attribute MUST be omitted or have a value of """ +
            """urn:oasis:names:tc:SAML:2.0:nameid-format:entity."""),

    SAMLProfiles_4_1_4_2_d("""[A Response] MUST contain at least one <Assertion>."""),

//    SAMLProfiles_4_1_4_2e("""If multiple assertions are included, then each assertion's <Subject> element MUST refer to
// the same principal."""),

    SAMLProfiles_4_1_4_2_f("""Any assertion issued for consumption using this profile MUST contain a <Subject> element."""),

    SAMLProfiles_4_1_4_2_g("""Any assertion issued for consumption using this profile MUST contain a <Subject> element """ +
            """with at least one <SubjectConfirmation> element containing a Method of """ +
            """urn:oasis:names:tc:SAML:2.0:cm:bearer."""),

    SAMLProfiles_4_1_4_2_h("""At least one bearer <SubjectConfirmation> element MUST contain a """ +
            """<SubjectConfirmationData> element that itself MUST contain a Recipient attribute containing the service """ +
            """provider's assertion consumer service URL and a NotOnOrAfter attribute that limits the window during """ +
            """which the assertion can be [E52]confirmed by the relying party. It MAY also contain an Address """ +
            """attribute limiting the client address from which the assertion can be delivered. It MUST NOT contain a """ +
            """NotBefore attribute. If the containing message is in response to an <AuthnRequest>, then the """ +
            """InResponseTo attribute MUST match the request's ID."""),

    SAMLProfiles_4_1_4_2_i("""The set of one or more bearer assertions MUST contain at least one <AuthnStatement> that """ +
            """reflects the authentication of the principal to the identity provider."""),

    SAMLProfiles_4_1_4_2_j("""If the identity provider supports the Single Logout profile, defined in Section 4.4, any """ +
            """authentication statements MUST include a SessionIndex attribute to enable per-session logout requests """ +
            """by the service provider."""),

    SAMLProfiles_4_1_4_2_k("""Each bearer assertion MUST contain an <AudienceRestriction> including the service """ +
            """provider's unique identifier as an <Audience>."""),

    SAMLProfiles_4_1_4_5("""If the HTTP POST binding is used to deliver the <Response>, [E26]each assertion MUST be """ +
            """protected by a digital signature. This can be accomplished by signing each individual element or by """ +
            """<Assertion> signing the <Response> element."""),

    /***************
     *
     * CORE
     *
     ***************/

    SAMLCore_1_3_1_a("""Unless otherwise noted in this specification or particular profiles, all strings in SAML """ +
            """messages MUST consist of at least one non-whitespace character (whitespace is defined in the XML """ +
            """Recommendation [XML] Section 2.3)."""),

    SAMLCore_1_3_2_a("""Unless otherwise indicated in this specification, all URI reference values used within """ +
            """SAML-defined elements or attributes MUST consist of at least one non-whitespace character, and are """ +
            """REQUIRED to be absolute [RFC 2396]."""),

    SAMLCore_1_3_3("""All SAML time values have the type xs:dateTime, which is built in to the W3C XML Schema """ +
            """Datatypes specification [Schema2], and MUST be expressed in UTC form, with no time zone component."""),

    SAMLCore_1_3_4("""Where a data object declares that it has a particular identifier, there MUST be exactly one such """ +
            """declaration."""),

    SAMLCore_2_2_4_a("""The Type attribute [for an EncryptedData] SHOULD be present and, if present, MUST contain a """ +
            """value of http://www.w3.org/2001/04/xmlenc#Element."""),

    //todo SAMLCore_2_2_4_b("""The encrypted content MUST contain an element that has a type of NameIDType or
    // AssertionType, or a type that is derived from BaseIDAbstractType, NameIDType, or AssertionType."""),

    //todo SAMLCore_2_2_4_c("""Encrypted identifiers are intended as a privacy protection mechanism when the plain-text
    // value passes through an intermediary. As such, the ciphertext MUST be unique to any given encryption operation.
    // For more on such issues, see [XMLEnc] Section 6.3."""),

    SAMLCore_2_2_3_a("""An xsi:type attribute MUST be used to indicate the actual statement type."""),

    SAMLCore_2_2_3_b("""An assertion with no statements MUST contain a <Subject> element. Such an assertion identifies """ +
            """a principal in a manner which can be referenced or confirmed using SAML methods, but asserts no further """ +
            """information associated with that principal."""),

    SAMLCore_2_3_3_a(""" The identifier for the version of SAML defined in this specification is '2.0'."""),

    SAMLCore_2_3_3_b("""[The Assertion's ID] is of type xs:ID, and MUST follow the requirements specified in Section """ +
            """1.3.4 for identifier uniqueness."""),

    SAMLCore_2_3_3_c("""The [assertion's] time instant of issue in UTC, as described in Section 1.3.3."""),

    SAMLCore_2_3_4_a("""The Type attribute [for an EncryptedData] SHOULD be present and, if present, MUST contain a """ +
            """value of http://www.w3.org/2001/04/xmlenc#Element."""),

    //todo SAMLCore_2_3_4_b("""The encrypted content MUST contain an element that has a type of or derived from
    // AssertionType."""),

    // todo SAMLCore_2_4_1_2_b("""SAML extensions MUST NOT add local (non-namespace-qualified) XML attributes or XML
    // attributes qualified by a SAML-defined namespace to the SubjectConfirmationDataType complex type or a derivation
    // of it; such attributes are reserved for future maintenance and enhancement of SAML itself."""),

    SAMLCore_2_4_1_2_b("""If both attributes are present, the value for NotBefore MUST be less than (earlier than) the """ +
            """value for NotOnOrAfter."""),

    SAMLCore_2_4_1_3("""Note that in accordance with [XMLSig], each <ds:KeyInfo> element MUST identify a single """ +
            """cryptographic key."""),

    SAMLCore_2_5_1_a("""An xsi:type attribute MUST be used [in the Condition element] to indicate the actual """ +
            """condition type."""),

    SAMLCore_2_5_1_b("""There MUST be at most one instance of [the OneTimeUse] element [under Conditions]."""),

    SAMLCore_2_5_1_c("""There MUST be at most one instance of [the ProxyRestriction] element [under Conditions]."""),

    SAMLCore_2_5_1_2("""If both attributes are present, the value for NotBefore MUST be less than (earlier than) the """ +
            """value for NotOnOrAfter."""),

    SAMLCore_2_5_1_5("""A SAML authority MUST NOT include more than one <OneTimeUse> element within a <Conditions> """ +
            """element of an assertion."""),

    SAMLCore_2_5_1_6_a("""Otherwise, any assertions so issued MUST themselves contain an <AudienceRestriction> element """ +
            """with at least one of the <Audience> elements present in the previous <ProxyRestriction> element, and no """ +
            """<Audience> elements present that were not in the previous <ProxyRestriction> element."""),

    SAMLCore_2_5_1_6_b("""A SAML authority MUST NOT include more than one <ProxyRestriction> element within a """ +
            """<Conditions> element of an assertion."""),

    SAMLCore_2_7_2("""Assertions containing <AuthnStatement> elements MUST contain a <Subject> element."""),

    SAMLCore_2_7_3("""Assertions containing <AttributeStatement> elements MUST contain a <Subject> element."""),

    SAMLCore_2_7_3_1_1("""If a SAML attribute includes a 'null' value, the corresponding <AttributeValue> element MUST""" +
            """ be empty and MUST contain the reserved xsi:nil XML attribute with a value of 'true' or '1'."""),

    SAMLCore_2_7_3_2_a("""The Type attribute [for an EncryptedData] SHOULD be present and, if present, MUST contain a """ +
            """value of http://www.w3.org/2001/04/xmlenc#Element."""),

    // todo SAMLCore_2_7_3_2_b("""The encrypted content MUST contain an element that has a type of or derived from
    // AttributeType."""),

    SAMLCore_2_7_4("""Assertions containing <AuthzDecisionStatement> elements MUST contain a <Subject> element."""),

    SAMLCore_3_2_1_a("""An identifier for the request. It is of type xs:ID and MUST follow the requirements specified """ +
            """in Section 1.3.4 for identifier uniqueness."""),

    SAMLCore_3_2_1_b("""The identifier for the version of SAML defined in this specification is '2.0'."""),

    SAMLCore_3_2_1_c("""The time value is encoded in UTC, as described in Section 1.3.3."""),

    SAMLCore_3_2_2_a("""It is of type xs:ID, and MUST follow the requirements specified in Section 1.3.4 for """ +
            """identifier uniqueness."""),

    SAMLCore_3_2_2_b("""If the response is not generated in response to a request, or if the ID attribute value of a """ +
            """request cannot be determined (for example, the request is malformed), then this attribute MUST NOT be """ +
            """present. Otherwise, it MUST be present and its value MUST match the value of the corresponding """ +
            """request's ID attribute."""),

    SAMLCore_3_2_2_c("""The identifier for the version of SAML defined in this specification is '2.0'."""),

    SAMLCore_3_2_2_d("""The time value is encoded in UTC, as described in Section 1.3.3."""),

    SAMLCore_3_2_2_e("""If it is present, the actual recipient MUST check that the URI reference identifies the """ +
            """location at which the message was received. If it does not, the response MUST be discarded. Some """ +
            """protocol bindings may require the use of this attribute (see [SAMLBind])."""),

    SAMLCore_3_2_2_2("The value of the topmost <StatusCode> element MUST be from the top-level list provided in this " +
    "section.\n" +
            "The permissible top-level <StatusCode> values are as follows: \n " +
            "- urn:oasis:names:tc:SAML:2.0:status:Success \n " +
            "- urn:oasis:names:tc:SAML:2.0:status:Requester \n " +
            "- urn:oasis:names:tc:SAML:2.0:status:Responder \n " +
            "- urn:oasis:names:tc:SAML:2.0:status:VersionMismatch"),

    SAMLCore_3_3_2_2_a("""If the SessionIndex attribute is present in the query, at least one <AuthnStatement> element """ +
            """in the set of returned assertions MUST contain a SessionIndex attribute that matches the SessionIndex """ +
            """attribute in the query."""),

    SAMLCore_3_3_2_2_b("""If the <RequestedAuthnContext> element is present in the query, at least one """ +
            """<AuthnStatement> element in the set of returned assertions MUST contain an <AuthnContext> element that """ +
            """satisfies the element in the query (see Section 3.3.2.2.1)."""),

    SAMLCore_3_3_2_3("""A single query MUST NOT contain two <saml:Attribute> elements with the same Name and """ +
            """NameFormat values (that is, a given attribute MUST be named only once in a query)."""),

    SAMLCore_3_4("""When a principal (or an agent acting on the principal's behalf) wishes to obtain assertions """ +
            """containing authentication statements to establish a security context at one or more relying parties, it """ +
            """can use the authentication request protocol to send an <AuthnRequest> message element to a SAML """ +
            """authority and request that it return a <Response> message containing one or more such assertions. Such """ +
            """assertions MAY contain additional statements of any type, but at least one assertion MUST contain at """ +
            """least one authentication statement. A SAML authority that supports this protocol is also termed an """ +
            """identity provider."""),

//    todo SAMLCore_3_4_1_1_a("""The special Format value urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted indicates
// that the resulting assertion(s) MUST contain """ +
//            """<EncryptedID> elements instead of plaintext."""),

    SAMLCore_3_7_1("""This specification further restricts the schema by requiring that the Reason attribute MUST be in""" +
            """ the form of a URI reference."""),

    SAMLCore_5_4_1("""SAML assertions and protocols MUST use enveloped signatures when signing assertions and protocol """ +
            """messages."""),

    SAMLCore_5_4_2_a("""SAML assertions and protocol messages MUST supply a value for the ID attribute on the root """ +
            """element of the assertion or protocol message being signed."""),

    SAMLCore_5_4_2_b("""Signatures MUST contain a single <ds:Reference> containing a same-document reference to the """ +
            """ID attribute value of the root element of the assertion or protocol message being signed. For example, """ +
            """if the ID attribute value is 'foo', then the URI attribute in the <ds:Reference> element MUST be '#foo'."""),

    SAMLCore_5_4_2_b1("""Signatures MUST contain a single <ds:Reference>."""),

    // todo SAMLCore_6_1_a("""Encrypted data and [E30]zero or more encrypted keys MUST replace the plaintext information
    // in the same location within the XML instance."""),

    SAMLCore_6_1_b("""The <EncryptedData> element's Type attribute SHOULD be used and, if it is present, MUST have the """ +
            """value http://www.w3.org/2001/04/xmlenc#Element."""),

    /***************
     *
     * BINDINGS
     *
     ***************/

//    # todo SAMLBindings_3_1_1_b("""Implementations MUST carefully sanitize the URL schemes they permit (for example,
// disallowing \ # anything but """http""" or """https"""), and should disallow unencoded characters that may be used in
// mounting such attacks."""),

    SAMLBindings_3_1_2_1("""servers MUST authenticate to clients using a X.509 v3 certificate"""),

    SAMLBindings_3_4_3_a("""RelayState data MAY be included with a SAML protocol message transmitted with this """ +
            """binding. The value MUST NOT exceed 80 bytes in length"""),

    SAMLBindings_3_4_3_b1("""If a SAML request message is accompanied by RelayState data, then the SAML responder... """ +
            """MUST place the exact data it received with the request into the corresponding RelayState parameter in """ +
            """the response."""),

    SAMLBindings_3_4_4_a("""A URL encoding MUST place the message entirely within the URL query string, and MUST """ +
            """reserve the rest of the URL for the endpoint of the message recipient"""),

    SAMLBindings_3_4_4_1("""Any signature on the SAML protocol message, including the <ds:Signature> XML element """ +
            """itself, MUST be removed"""),

    SAMLBindings_3_4_4_1_a("""The compressed data is subsequently base64-encoded according to the rules specified in """ +
            """IETF RFC 2045 [RFC2045]. Linefeeds or other whitespace MUST be removed from the result."""),

    SAMLBindings_3_4_4_1_a1("""The compressed data is subsequently base64-encoded according to the rules specified in """ +
            """IETF RFC 2045 [RFC2045]."""),

    SAMLBindings_3_4_4_1_a2("""Linefeeds or other whitespace MUST be removed from the [base64 encoded] result."""),

//    # todo Would need to change the pluggable portion to verify all of these below
//    SAMLBindings_3_4_4_1_b("""The base-64 encoded data is then URL-encoded, and added to the URL as a query string """ +
//        """parameter which MUST be named SAMLRequest (if the message is a SAML request) or SAMLResponse (if the message
// is a SAML response)."""),

    SAMLBindings_3_4_4_1_b1("""The base-64 encoded data is then URL-encoded"""),

    SAMLBindings_3_4_4_1_b2("""[The SAML Response is] added to the URL as a query string parameter which MUST be """ +
            """named...SAMLResponse"""),

    SAMLBindings_3_4_4_1_c1("""If RelayState data is to accompany the SAML protocol message, it MUST be URL-encoded"""),

    SAMLBindings_3_4_4_1_c2("""If RelayState data is to accompany the SAML protocol message, it MUST be... """ +
            """placed in an additional query string parameter named RelayState."""),

    SAMLBindings_3_4_4_1_d1("""The signature algorithm identifier MUST be included as an additional query string """ +
            """parameter, named SigAlg."""),

    SAMLBindings_3_4_4_1_d2("""[SigAlg] MUST be a URI that identifies the algorithm used to sign the URL-encoded SAML """ +
            """protocol message, specified according to [XMLSig] or whatever specification governs the algorithm."""),

    SAMLBindings_3_4_4_1_e("""To construct the signature, a string consisting of the concatenation of the RelayState """ +
            """(if present), SigAlg, and SAMLRequest (or SAMLResponse ) query string parameters (each one URL-encoded) """ +
            """is constructed in one of the following ways (ordered as below): """ +
            """SAMLRequest=value&RelayState=value&SigAlg=value """ +
            """SAMLResponse=value&RelayState=value&SigAlg=value"""),

    SAMLBindings_3_4_4_1_f1("""The signature value MUST be encoded using the base64 encoding (see RFC 2045 [RFC2045]) """ +
            """with any whitespace removed"""),

    SAMLBindings_3_4_4_1_f2("""The signature value MUST be included as a query string parameter named Signature."""),

//    todo SAMLBindings_3_4_4_1_g("""The following signature algorithms (see [XMLSig]) and their URI representations MUST
// be supported with this encoding mechanism: \n""" +
//            """• DSAwithSHA1 – http://www.w3.org/2000/09/xmldsig#dsa-sha1 \n""" +
//            """• RSAwithSHA1 – http://www.w3.org/2000/09/xmldsig#rsa-sha1"""),

    SAMLBindings_3_4_5_2_a1("""If the message is signed, the Destination XML attribute in the root SAML element of the """ +
            """protocol message MUST contain the URL to which the sender has instructed the user agent to deliver the """ +
            """message."""),

//    todo SAMLBindings_3_4_5_2_a2("""If the message is signed, the... recipient MUST then verify that the [Destination]
// value matches the location at which the message has been received."""),

    SAMLBindings_3_4_6_a("""HTTP interactions during the message exchange MUST NOT use HTTP error status codes to """ +
            """indicate failures in SAML processing, since the user agent is not a full party to the SAML protocol """ +
            """"exchange."""),

    SAMLBindings_3_5_3_a("""The [RelayState] value MUST NOT exceed 80 bytes in length"""),

    SAMLBindings_3_5_3_b("""If a SAML request message is accompanied by RelayState data, then the SAML responder... """ +
            """MUST place the exact data it received with the request into the corresponding RelayState parameter in """ +
            """the response."""),

    SAMLBindings_3_5_4_a("""A SAML protocol message is form-encoded by applying the base-64 encoding rules to the XML """ +
            """representation of the message and placing the result in a hidden form control within a form as defined """ +
            """by [HTML401] Section 17."""),

    SAMLBindings_3_5_4_a1("""A SAML protocol message is form-encoded by applying the base-64 encoding rules to the XML """ +
            """representation of the message"""),

    SAMLBindings_3_5_4_a2("""A SAML protocol message is form-encoded by... placing the result in a hidden form control """ +
            """within a form as defined by [HTML401] Section 17."""),

    SAMLBindings_3_5_4_b("""If the message is a SAML request, then the form control MUST be named SAMLRequest. If """ +
            """the message is a SAML response, then the form control MUST be named SAMLResponse. Any additional form """ +
            """controls or presentation MAY be included but MUST NOT be required in order for the recipient to process """ +
            """the message"""),

    SAMLBindings_3_5_4_b1("""If the message is a SAML request, then the form control MUST be named SAMLRequest. If the """ +
            """message is a SAML response, then the form control MUST be named SAMLResponse."""),

    SAMLBindings_3_5_4_c("""If a \"RelayState\" value is to accompany the SAML protocol message, it MUST be placed """ +
            """in an additional hidden form control named RelayState within the same form with the SAML message."""),

    SAMLBindings_3_5_4_d("""The action attribute of the form MUST be the recipient's HTTP endpoint for the protocol or """ +
            """profile using this binding to which the SAML message is to be delivered. The method attribute MUST """ +
            """be "POST"."""),

    SAMLBindings_3_5_4_d1("""The action attribute of the form MUST be the recipient's HTTP endpoint for the """ +
            """protocol or profile using this binding to which the SAML message is to be delivered."""),

    SAMLBindings_3_5_4_d2("""The method attribute [of the form] MUST be "POST"."""),

//    todo SAMLBindings_3_5_4_c("""SAML message could not be decoded. SAML messages should be base-64 encoded."""),

    SAMLBindings_3_5_5_2_a("""If the message is signed, the Destination XML attribute in the root SAML element of the """ +
            """protocol message MUST contain the URL to which the sender has instructed the user agent to deliver the """ +
            """message."""),

    SAMLBindings_3_5_6_a("""HTTP interactions during the message exchange MUST NOT use HTTP error status codes """ +
            """to indicate failures in SAML processing, since the user agent is not a full party to the SAML protocol """ +
            """exchange."""),

    /***************
     *
     * XML Datatype Schema
     *
     ***************/

    XMLDatatypesSchema_3_2_7("""See XML Schema 2 [https://www.w3.org/TR/xmlschema-2/] section 3.2.7 for more """ +
            """information"""),

    XMLDatatypesSchema_3_2_7_1_a("""if [the year has] more than four digits, leading zeros are prohibited"""),

    XMLDatatypesSchema_3_2_7_1_b("""'0000' is prohibited [as the year]"""),

    XMLDatatypesSchema_3_2_7_1_c("""a plus sign is not permitted [in the year]"""),

    /***************
     *
     * XML Signature Syntax and Processing
     *
     ***************/

    XMLSignature_4_5("""compliant versions [of KeyInfo] MUST implement KeyValue""")
}
