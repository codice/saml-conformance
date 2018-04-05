#The [DDF](https://github.com/codice/ddf) SAML Implementation

## Steps to Test DDF's IDP
* Start and install DDF
* Copy the contents of `samlconf-sp-metadata.xml` to `AdminConsole -> Security -> Configuration -> IdPServer -> SP Metadata`.
* If not on localhost, copy DDF's IDP metadata from `https://<hostname>:<port>/services/idp/login/metadata` 
to the file `<samlconf>/implementations/ddf/ddf-idp-metadata.xml` where `<samlconf>` is the root directory of the test kit distribution.
* Run `<samlconf>/bin/samlconf` where `<samlconf>` is the root directory of the test kit distribution. (no parameters needed since it points to DDF's implementation by default)