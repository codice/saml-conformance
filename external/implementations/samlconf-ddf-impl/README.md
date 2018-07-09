# The [DDF](https://github.com/codice/ddf) SAML Implementation
## Known Compliance Issues
| Issue                                                                                           | Section          | Specification Snippet
| ---------------------------------------------------------------------------------------------------------------------- | ---------------- | -----------------------
| When the IdP is issuing LogoutRequests to SPs, the NameID is missing all of its XML attributes                         | Profiles 4.4.4.1 | The principal MUST be identified in the request using an identifier that strongly matches the identifier in the authentication assertion the requester issued or received regarding the session being terminated, per the matching rules defined in Section 3.3.4 of [SAMLCore].
| In the Response, NameIDs do not have the format or the SPNameQualifier specified in the AuthnRequest's NameIDPolicy    | Core 3.4.1.1     | When a Format defined in Section 8.3 other than urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified or urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted is used, then if the identity provider returns any assertions: the Format value of the \<NameID> within the \<Subject> of any \<Assertion> MUST be identical to the Format value supplied in the \<NameIDPolicy> and if SPNameQualifier is not omitted in \<NameIDPolicy>, the SPNameQualifier value of the \<NameID> within the \<Subject> of any \<Assertion> MUST be identical to the SPNameQualifier value supplied in the \<NameIDPolicy>.
| The IdP ignores the \<Subject> element on the \<AuthnRequest> instead of validating it                                 | Profiles 4.1.4.1 | Note that the service provider MAY include a \<Subject> element in the request that names the actual identity about which it wishes to receive an assertion. This element MUST NOT contain any \<SubjectConfirmation> elements. If the identity provider does not recognize the principal as that identity, then it MUST respond with a \<Response> message containing an error status and no assertions.


## Steps to Test DDF's IDP
* Start and install DDF
* DDF does not support having multiple `EntityDescriptor` elements inside a `EntitiesDescriptor` element. In order to work around this:
    * From the `samlconf-sp-metadata.xml` file, copy the first `EntityDescriptor` element and all of its contents. Note: Make sure **not** to include the `EntitiesDescriptor` element or the second `EntityDescriptor` element.
    * Paste that into `AdminConsole -> Security -> Configuration -> IdPServer -> SP Metadata` as a new entry.
    * Do the same copy-paste steps but copying the **second** `EntityDescriptor` element.
* If not on localhost, copy DDF's IDP metadata from `https://<hostname>:<port>/services/idp/login/metadata` 
to the file `<samlconf>/implementations/ddf/ddf-idp-metadata.xml` where `<samlconf>` is the root directory of the test kit distribution.
* From the root of the saml-conformance soruce directory, run `deployment/distribution/build/install/samlconf/bin/samlconf -l`. Note: This assumes the project has been succesfully built.