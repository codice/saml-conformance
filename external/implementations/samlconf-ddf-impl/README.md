<!--
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
-->

# The [DDF](https://github.com/codice/ddf) SAML Implementation
## Known Compliance Issues
| Issue                                                                                           | Section          | Specification Snippet
| ---------------------------------------------------------------------------------------------------------------------- | ---------------- | -----------------------
| Does not respond with SAML error responses with a top­level status code but throws an exception instead.| Core 3.4.1.4 | If the responder is unable to authenticate the presenter or does not recognize the requested subject, or if prevented from providing an assertion by policies in effect at the identity provider (for example the intended subject has prohibited the identity provider from providing assertions to the relying party), then it MUST return a `<Response>` with an error `<Status>`.
| When the IdP is issuing LogoutRequests to SPs, the `NameID` is missing all of its XML attributes. | Profiles 4.4.4.1 | The principal MUST be identified in the request using an identifier that strongly matches the identifier in the authentication assertion the requester issued or received regarding the session being terminated, per the matching rules defined in Section 3.3.4 of SAMLCore.

## Steps to Test DDF's IDP
* Start and install DDF. \
**NOTE**: If installing through the UI, the `users.attributes` file under `etc/` must be changed so that the admin email is `admin@localhost.local` instead of `admin@localhost`.
    * Copy the content of the [`samlconf-sp-metadata.xml`](../../../deployment/distribution/src/main/resources/samlconf-sp-metadata.xml) file.
    * On DDF, navigate to `AdminConsole -> Security -> Configuration -> IdPServer -> SP Metadata`
    * Paste the content as a new entry.
* If DDF, hostname and port was changed during installation (i.e. it's not on `https://localhost:8993/`)
    * Copy DDF's IDP metadata from `https://<hostname>:<port>/services/idp/login/metadata`
    * Paste the content to the [ddf-idp-metadata.xml](../samlconf-ddf-impl/src/main/resources/ddf-idp-metadata.xml) file
    under `<samlconf>/implementations/ddf/ddf-idp-metadata.xml` where `<samlconf>` is the root directory of the test kit distribution.
* Run the `samlconf` script under `deployment/distribution/build/install/samlconf/bin` with `-i ../implementations/ddf -l`.