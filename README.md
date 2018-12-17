<!--
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
-->

# The Security Assertion Markup Language (SAML) Conformance Test Kit (CTK)

[![Download the latest release at https://github.com/codice/saml-conformance/releases/tag/saml-ctk-1.0](https://img.shields.io/badge/Download-1.0-green.svg)](http://artifacts.codice.org/content/repositories/releases/org/codice/samlconf/samlconf/1.0/)
[![Join the Google Group at https://groups.google.com/forum/#!forum/saml-ctk](https://img.shields.io/badge/Google%20Group-Join%20the%20chat-blue.svg)](https://groups.google.com/forum/#!forum/saml-ctk)

The SAML Conformance Test Kit is intended to be a set of blackbox tests that verify the conformance of an Identity Provider (IdP) to the [SAML V2.0 Standard Specification](https://wiki.oasis-open.org/security/FrontPage).

Note the following before running the tests:
  * This test kit only supports SAML Version 2.0. All other versions are not supported.
  * This test kit does not support proxying.
  * Currently, the CTK only tests POST and Redirect bindings.
  * Single Sign-On and Single Logout are the only two protocols tested.
  * Only statements containing the keywords `MUST`, `MUST NOT` and `REQUIRED` are tested.
  * Some `MUST`s are hard to test. For a full list, visit the [Not Tested List](ctk/idp/NotTested.md).
  * This test kit includes built-in support for Keycloak and Distributed Data Framework (DDF) Identity Providers.

## Building
To build the project execute `gradlew build`.
After the build, the distribution zip will be located at `deployment/distribution/build/distributions`.
The unzipped distribution can be found at `deployment/distribution/build/install/samlconf`.

## Running

#### Connect to an Identity Provider
The SAML-CTK includes built-in support for [Keycloak](https://github.com/keycloak/keycloak) and [Distributed Data Framework (DDF)](https://github.com/codice/ddf).
If the IdP being tested is not Keycloak or DDF see [Developing a plugin](#developing-a-plugin) to test your IdP.

In general, to connect an IdP with the CTK, the IdP needs the [CTK SP metadata](deployment/distribution/src/main/resources/samlconf-sp-metadata.xml) and vice-versa.
If you are testing Keycloak or DDF, see their corresponding documentation on how to connect them to the test kit:
- [Keycloak Documentation](external/implementations/samlconf-keycloak-impl/README.md)
- [DDF documentation](external/implementations/samlconf-ddf-impl/README.md)

#### Run the tests
After a successful gradle build, tests can be run with the generated `samlconf` scripts under `deployment/distribution/build/install/samlconf/bin`.
Run the executable `samlconf` (*NIX) or `samlconf.bat` (Windows).

The `samlconf` script may take the following parameters:

    NAME
           SamlConf - Runs the SAML Conformance Tests against an IdP

    SYNOPSIS
           samlconf [arguments ...]

    DESCRIPTION
           Runs the SAML Conformance Tests which test the compliance of an IdP with the SAML Specifications.
           If a compliance issue is identified, a SAMLComplianceException will be thrown with an explanation
           of the error and a direct quote from the specification. Tests will not run if the corresponding
           endpoints do not exist in the IdP's metadata. All of the parameters are optional and if they are
           not provided, the default values will use Distributed Data Framework (DDF)'s parameters.

    OPTIONS
           -ddf, --ddf
                Runs the DDF profile. If provided runs the optional SAML V2.0 Standard
                Specification rules required by DDF.

           -debug, --debug
                Enables debug mode which enables more logging. This mode is off by default.

           -h, --help
		        Displays the possible arguments.

           -i path, --implementation=path
                The path to the directory containing the implementation's plugin and metadata.
                The default value is /implementations/ddf.

           -l, --lenient
                When an error occurs, the SAML V2.0 Standard Specification requires an IdP to
                respond with a 200 HTTP status code and a valid SAML response containing an
                error <StatusCode>.
                If the -l flag is given, this test kit will allow HTTP error status codes as
                a valid error response (i.e. 400's and 500's).
                If it is not given, this test kit will only verify that a valid SAML error
                response is returned.

           -u username:password, --userLogin=username:password
                The username and password to use when logging in.
                The default value is admin:admin.

## Developing

#### Developing a plugin

Before testing an IdP, it has to be connected with the SAML-CTK. To do so, a custom plugin is required.

###### Why is a plugin required?

When logging in to an IdP using the Single Sign-On protocol, there are 6 steps:

1. HTTP Request to Service Provider
1. Service Provider Determines Identity Provider
1. `<AuthnRequest>` issued by Service Provider to Identity Provider
1. Identity Provider identifies Principal
1. Identity Provider issues `<Response>` to Service Provider
1. Service Provider grants or denies access to Principal

The specification mentions that in step 4, "the principal is identified by the identity provider by some means outside the scope of \[the Single Sign-On\] profile".
Since the authentication step is implementation specific, each IdP must write a plugin which will process the authentication of a principal.
See [4.1 Web Browser SSO Profile](https://www.oasis-open.org/committees/download.php/56782/sstc-saml-profiles-errata-2.0-wd-07.pdf) for more information on the different steps for the SSO profile.

###### How to implement a plugin jar?

1. Implement a plugin jar for the IdP's authentication implementation. \
Write a Java or Kotlin class that implements the [IdpSSOResponder](external/samlconf-plugins-api/src/main/java/org/codice/compliance/saml/plugin/IdpSSOResponder.java) interface. \
[DDFIdpSSOResponderProvider](external/implementations/samlconf-ddf-impl/src/main/kotlin/org/codice/compliance/saml/plugin/ddf/DDFIdpSSOResponderProvider.kt) and
[KeycloakIdpSSOResponderProvider](external/implementations/samlconf-keycloak-impl/src/main/kotlin/org/codice/compliance/saml/plugin/keycloak/KeycloakIdpSSOResponderProvider.kt) can be used as examples. \
**NOTE**: The implementation class is implementing a Java service therefore either
   * the `@MetaInfServices` annotation should be used (which uses the kapt plugin) or
   * a hand-crafted services reference file `META-INF/services/org.codice.compliance.saml.plugin.IdpSSOResponder` will need to be added to the jar (see below)
1. Package that file into a jar.
1. Place the jar from step 1 and the IdP's metadata into a directory.
1. Setup your IdP.
1. Configure your IdP with the test kit's [SP metadata](deployment/distribution/src/main/resources/samlconf-sp-metadata.xml).
1. The directory from step 3 should be referred to with the `-i` option when running tests. (See [Run the tests](#run-the-tests))

#### Formatting
The project uses [Spotless](https://github.com/diffplug/spotless) to ensure consistent style. Any style violations noted by Spotless can easily be resolved by running `./gradlew spotlessApply`.

#### Project Structure
This section will briefly talk about the project structure.

```
.
├── ctk - test related modules
│   │
│   ├── common - classes relating to utility and verification of the test classes
│   │               NOTE: Schema verification is run before tests and verifications.
│   │
│   └── idp - tests being written against a SAML IdP. The `src` directory of the module is organized
│             by the SAML specification as follows:
│              * Package: Based on Profile (i.e. WebSSO, Single Logout)
│                * Class: Based on Binding (i.e. POST, REDIRECT, ARTIFACT)
│
├── deployment - the project's full package deployment
│   │
│   ├── distribution - runtime elements including scripts, jars, and configurations
│   │
│   └── docker - logic for building a Docker image. Docker is used exclusively for our Jenkins builds.
│                To build a docker image, execute `gradlew build docker`. The docker image can also
│                be found on Docker Hub at https://hub.docker.com/r/codice/samlconf/.
│
├── external - files related to a specific SAML implementing product
│   │
│   ├── samlconf-plugins-api -  API that must be implemented for a SAML product in order to run this
│   │                           test kit against that product
│   │
│   └── implementations - implementations of the API for specific SAML products
│       │
│       ├── samlconf-ddf-impl - plugin and IdP metadata XML for the DDF implementation of IdP
│       │
│       └── samlconf-keycloak-impl - plugin and IdP metadata XML for the Keycloak implementation of IdP
│
└── library - Java classes copied from DDF to support operations outside the scope of the test code,
              e.g. signature validation using x509 certificates.
```

## References
  * SAML-CTK Forum: https://groups.google.com/forum/#!forum/saml-ctk
  * FICAM: https://www.idmanagement.gov/wp-content/uploads/sites/1171/uploads/SAML2_1.0.2_Functional_Reqs.pdf
  * SAML: https://wiki.oasis-open.org/security/FrontPage

## Copyright / License
Copyright (c) Codice Foundation

This is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License
as published by the Free Software Foundation, either version 3 of the License, or any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public License is distributed along with this program and can be found at
<http://www.gnu.org/licenses/lgpl.html>.
