# SAML Conformance Test Kit
This project is intended to be a set of blackbox tests that verify the conformance of an IdP/SP to the SAML Spec.
It is currently a prototype being actively developed.

FICAM: https://www.idmanagement.gov/wp-content/uploads/sites/1171/uploads//SAML2_1.0.2_Functional_Reqs.pdf

SAML: https://wiki.oasis-open.org/security/FrontPage

ECP: http://docs.oasis-open.org/security/saml/Post2.0/saml-ecp/v2.0/saml-ecp-v2.0.html

## idp
This module will contain all tests being written against a SAML IdP. 
Currently just has sub-directories for Web SSO and Single Logout, but that list will grow.

Current state: Two tests for Web SSO (post and redirect). 
Tests will be written against the IdP on DDF master for now.

## security-common
This module contains an assortment of Java classes that have been copied over from DDF to support parsing SAML metadata for the tests.

## ddf-plugins
This module contains the ServiceProvider plugins that are used to connect with
a DDF IdP. It should also be used as the model for building plugins for connecting
with other IdPs for compliance testing. The generated jar file from this module
needs to be installed to a deployment directory of the user's choosing and then
referred to by system property when running tests.

e.g. If the ServiceProvider plugin jar(s) are copied to `/home/saml-conform/deploy`
then the tests should be invoked with `-Dsaml.plugin.deployDir=/home/saml-conform/deploy`.

# Setup
- First, ensure the plugins you will be using are built and deployed to a
  deployment directory. If running against DDF, the easiest way to accomplish this
  is to run `mvn clean install -DskipTests=true` first and then copy the jar file
  generated in the `ddf-plugins` module to a deploy directory.
- Have a running DDF master instance.
- Run `mvn clean install -Dsaml.plugin.deployDir=[DEPLOY DIRECTORY]` or run
the test from IntelliJ setting the `saml.plugin.deployDir` property as appropriate.

## TODO:
- Determine good directory structure (this will happen over time as we add more tests)
- Determine what inputs the test suite will need (thinking just giving it the IdP/SP metadata)
- Determine the combinations of SP's that we want to test with
  - DDF IdP/SP
  - Shibboleth SP and DDF IdP
  - Shibboleth IdP and DDF IdP
  - Spring SP and DDF IdP

## References:
 - http://kotlinlang.org/docs/reference/
 - https://github.com/kotlintest/kotlintest/blob/master/doc/reference.md
 - https://try.kotlinlang.org/#/Kotlin%20Koans/Introduction/Hello,%20world!/Task.kt