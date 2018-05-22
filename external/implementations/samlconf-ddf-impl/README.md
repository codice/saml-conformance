#The [DDF](https://github.com/codice/ddf) SAML Implementation

## Steps to Test DDF's IDP
* Start and install DDF
* DDF does not support having multiple `EntityDescriptor` elements inside a `EntitiesDescriptor` element. In order to work around this:
    * From the `samlconf-sp-metadata.xml` file, copy the first `EntityDescriptor` element and all of its contents. Note: Make sure **not** to include the `EntitiesDescriptor` element or the second `EntityDescriptor` element.
    * Paste that into `AdminConsole -> Security -> Configuration -> IdPServer -> SP Metadata` as a new entry.
    * Do the same copy-paste steps but copying the **second** `EntityDescriptor` element.
* If not on localhost, copy DDF's IDP metadata from `https://<hostname>:<port>/services/idp/login/metadata` 
to the file `<samlconf>/implementations/ddf/ddf-idp-metadata.xml` where `<samlconf>` is the root directory of the test kit distribution.
* From the root of the saml-conformance GitHub repo, run `deployment/distribution/build/install/samlconf/bin/samlconf -l`. Note: This assumes the project has been succesfully built.