# The [Keycloak](https://github.com/keycloak/keycloak) SAML Implementation

## Steps to Test Keycloak's IDP
* Download Keycloak "Server" from [Keycloak Downloads](https://www.keycloak.org/downloads.html).
* Unzip and run in standalone mode. Then setup an account with "admin" for both username and password. Then login.
(Steps 2.1-2.4 in the [Keycloak Getting Started Guide](http://www.keycloak.org/docs/latest/getting_started/index.html#booting-the-server)).
* Go to the Users tab and click the View All Users button.
* Select the admin user and enter an email address in the form of an `addr-spec` as defined in [IETF RFC 2822](https://www.rfc-editor.org/info/rfc2822) under the Email field. Click Save.
* Keycloak does not support having multiple `EntityDescriptor` elements inside a `EntitiesDescriptor` element. In order to work around this:
    * Create two new xml files (doesn't matter what they're named)
    * From the `samlconf-sp-metadata.xml` file, copy the first `EntityDescriptor` element and all of its contents. Note: Make sure **not** to include the `EntitiesDescriptor` element or the second `EntityDescriptor` element.
    * Paste that into the first new xml file.
    * Do the same copy-paste steps but copying the **second** `EntityDescriptor` element into the second new xml file. Delete the XML comment inside this `EntityDescriptor` since this will cause issues for Keycloak parsing it.
* For each of the two new xml files:
    * Under the Clients tab, click the Create button in the top-right.
    * Under Import, click Select File and select the new xml file.
    * Click the Save button.
* From the root of the saml-conformance source directory, run `cd deployment/distribution/build/install/samlconf && bin/samlconf -i implementations/keycloak -l`.