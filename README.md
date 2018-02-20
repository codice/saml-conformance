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

## prototype-kotlin
This module contains requests and responses captured from DDF and Spring Security's SP

## security-common
This module contains an assortment of Java classes that have been copied over from DDF to support parsing SAML metadata for the tests.


# Setup
- Have a running DDF master instance.
- Run `mvn clean install` or run the test from IntelliJ.

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