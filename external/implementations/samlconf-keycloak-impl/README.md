# The [Keycloak](https://github.com/keycloak/keycloak) SAML Implementation
## Known Compliance Issues
| Issue| Section | Specification Snippet
| -----| ------- | ---------------------
| Does not respond with SAML error responses with a top­level status code.| Core 3.4.1.4 | If the responder is unable to authenticate the presenter or does not recognize the requested subject, or if prevented from providing an assertion by policies in effect at the identity provider (for example the intended subject has prohibited the identity provider from providing assertions to the relying party), then it MUST return a `<Response>` with an error `<Status>`.
| Does not validate that Relay States are less than or equal to 80 bytes.| Bindings 3.4.3 | RelayState data MAY be included with a SAML protocol message transmitted with this binding. The value MUST NOT exceed 80 bytes.
| Does not respond with `EncryptedID`’s (instead of `NameID`’s) when the AuthnRequest requests the encrypted format in the `NameIDPolicy`. | Core 3.4.1.1 | The special Format value `urn:oasis:names:tc:SAML:2.0:nameid­format:encryptedindicates` that the resulting assertion(s) MUST contain `<EncryptedID>` elements instead of plaintext. The underlying name identifier's unencrypted form can be of any type supported by the identity provider.
| Does not properly put the `SPNameQualifier` on `NameID`s in the Response, according the the `NameIDPolicy`. | Core 3.4.1.1 | If SPNameQualifier is not omitted in `<NameIDPolicy>`, the `SPNameQualifier` value of the `<NameID>` within the `<Subject>` of any `<Assertion>` MUST be identical to the `SPNameQualifier` value supplied in the `<NameIDPolicy>`.
| Does not provide a second­level status code of `PartialLogout` when the IdP gets an error in response to a LogoutRequest it sent to a second SP.| Core 3.7.3.2 | In the event that not all session participants successfully respond to these `<LogoutRequest>` messages (or if not all participants can be contacted), then the session authority MUST include in its `<LogoutResponse>` message a second­level status code of `urn:oasis:names:tc:SAML:2.0:status:PartialLogout` to indicate that not all other session participants successfully responded with confirmation of the logout.
| Does not put the `NotOnOrAfter` attribute on `LogoutRequests`.| Core 3.7.3.2 | When constructing a logout request message, the session authority MUST set the value of the `NotOnOrAfter` attribute of the message to a time value, indicating an expiration time for the message, after which the logout request may be discarded by the recipient.
| Does not attempt to send a `LogoutRequest` to the second SP when POST binding is used to login and logout.| Profiles 4.4.3.3 | To propagate the logout, the identity provider issues its own `<LogoutRequest>` to a session authority or participant in a session being terminated.

## Steps to Test Keycloak's IDP
* Download Keycloak "Server" from [Keycloak Downloads](https://www.keycloak.org/downloads.html).
* Unzip and run in standalone mode.
* Setup an account with `admin` for both username and password.
* Login

*See steps 2.1 to 2.4 in the [Keycloak Getting Started Guide](http://www.keycloak.org/docs/latest/getting_started/index.html#booting-the-server) for more detail on the above steps.*

* Go to the `Users` tab and click the `View All Users` button.
* Select the admin user and enter an email address in the form of an `addr-spec` as defined in [IETF RFC 2822](https://www.rfc-editor.org/info/rfc2822) under the Email field.
* Click Save.
* Provide the CTK SP metadata to Keycloak \
Keycloak does not support having multiple `EntityDescriptor` elements inside an `EntitiesDescriptor` element. \
In order to work around this:
    * Create two new xml files (the name doesn't matter)
    * From the [`samlconf-sp-metadata.xml`](../../../deployment/distribution/src/main/resources/samlconf-sp-metadata.xml) file, copy the **first** `EntityDescriptor` element and all of its contents. \
    **NOTE**: Make sure **NOT** to include the `EntitiesDescriptor` element or the second `EntityDescriptor` element.
    * Paste that into the **first** new xml file.
    * Copy the **second** `EntityDescriptor` element and all of its contents.
    * Paste that into the **second** new xml file. \
    **NOTE**: Delete the XML comment inside this `EntityDescriptor` since this will cause issues for Keycloak parsing it.
* For **each** of the two new xml files:
    * Under the `Clients` tab, click the `Create` button in the top-right.
    * Under `Import`, click `Select File` and select the new xml file.
    * Click the `Save` button.
* Run the `samlconf` script under `deployment/distribution/build/install/samlconf/bin` with `-i ../implementations/keycloak -l`.