<!--
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
-->

Welcome to the Security Assertion Markup Language (SAML) Conformance Test Kit (CTK)
===================================================================================
The SAML Conformance Test Kit is a set of blackbox tests that verify the conformance of an
Identity Provider (IdP) to the SAML V2.0 Standard Specification.

Note the following before running the tests:
  * This test kit only supports SAML Version 2.0. All other versions are not supported.
  * This test kit does not support proxying.
  * Currently, the CTK only tests POST and Redirect bindings.
  * Single Sign-On and Single Logout are the only two protocols tested.
  * Only statements containing the keywords `MUST`, `MUST NOT` and `REQUIRED` are tested.
  * Some `MUST`s are hard to test. For a full list, visit the [Not Tested List](../../../../../ctk/idp/NotTested.md).
  * This test kit includes built-in support for Keycloak and Distributed Data Framework (DDF) Identity Providers.

Getting Started
===============
For a SAML CTK source distribution, please read the README.md file at
https://github.com/codice/saml-conformance for instructions on building this test kit.

How to Run
==========
* Unzip the distribution.
* Run the executable at <distribution_home>/bin/samlconf (*NIX) or <distribution_home>/bin/samlconf.bat (Windows)

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


Identity Provider Support
=========================
This test kit includes built-in support for Keycloak and Distributed Data Framework (DDF).

  * To run the test against Distributed Data Framework (DDF):
    - Setup your DDF IdP.
    - Configure your IdP with the test kit's Service Provider (SP) metadata from `<distribution_home>/conf/samlconf-sp-metadata.xml`.
    - Run the `samlconf` script without a `-i` or with `-i <distribution_home>/implementations/ddf`.

See [the DDF setup documentation](../../../../../external/implementations/samlconf-ddf-impl/README.md)
for more information on setting up and testing DDF.

  * To run the test against Keycloak:
    - Setup your Keycloak IdP.
    - Configure your IdP with the test kit's Service Provider (SP) metadata from `<distribution_home>/conf/samlconf-sp-metadata.xml`.
    - Run the `samlconf` script with `-i <distribution_home>/implementations/keycloak`.

See [the Keycloak setup documentation](../../../../../external/implementations/samlconf-keycloak-impl/README.md)
for more information on setting up and testing Keycloak.

Additional Information
=====================

To run this test kit against other Identity Providers, see the README.md file at https://github.com/codice/saml-conformance.

Copyright / License
===================

Copyright (c) Codice Foundation

This is free software: you can redistribute it and/or modify it under the terms of the GNU Lesser General Public License
as published by the Free Software Foundation, either version 3 of the License, or any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
See the GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public License is distributed along with this program and can be found at
<http://www.gnu.org/licenses/lgpl.html>.

