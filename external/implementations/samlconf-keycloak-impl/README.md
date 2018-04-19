#The [Keycloak](https://github.com/keycloak/keycloak) SAML Implementation

## Steps to Test Keycloak's IDP
* Download Keycloak from [Keycloak Downloads](https://www.keycloak.org/downloads.html).
* Unzip and run in standalone mode. Then setup an account with "admin" for both username and password. Then login.
(Steps 2.1-2.4 in the [Keycloak Getting Started Guide](http://www.keycloak.org/docs/latest/getting_started/index.html#booting-the-server)).
* Go to the Users tab and click the View All Users button.
* Select the admin user and enter a valid email address under the Email field. Click Save.
* Under the Clients tab, click the Create button in the top-right.
* Under Import, click Select File and select the `samlconf-sp-metadata.xml` file.
* Click the Save button.
* Run `<samlconf>/bin/samlconf -i <samlconf>/implementations/keycloak`
where `<samlconf>` is the root directory of the test kit distribution.