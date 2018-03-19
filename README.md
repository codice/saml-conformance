# SAML Conformance Test Kit
This project is intended to be a set of blackbox tests that verify the conformance of an IdP/SP to the SAML Spec.
It is currently a prototype being actively developed.

FICAM: https://www.idmanagement.gov/wp-content/uploads/sites/1171/uploads/SAML2_1.0.2_Functional_Reqs.pdf

SAML: https://wiki.oasis-open.org/security/FrontPage

ECP: http://docs.oasis-open.org/security/saml/Post2.0/saml-ecp/v2.0/saml-ecp-v2.0.html

## Setup
To build the project, execute `gradle build` at the project root.
The `distribution/command-line` module will contain a full package of the deployment after the build.

Tests can be run with the `samlconf` script under `<PATH_TO_PROJECT>/distribution/command-line/build/distributions/samlconf-<VERSION>/bin/`.
Build the project will create the distribution, to unzip it, execute `gradle build installDist`, which will unzip it and place it under `build/install`.

The `samlconf` script takes multiple parameters:

```
NAME
       samlconf - Runs the SAML Conformance Tests against an IdP or an SP

SYNOPSIS
       samlconf [-i path] [--idpMetadata path]
           [-p path] [--plugins path] 

DESCRIPTION
       Runs the SAML Conformance Tests which tests the complance of an IdP and/or an SP
       with the SAML Specifications. If a compliance issue is identified, a 
       SAMLConformaceException will be throw with an explanation of the error an a direct
       quote from the specification. All of the parameters are optional and if they are 
       not provided, the default values will use DDF's parameters. All parameters must 
       be given one times.

OPTIONS
       -i path
           The path to the IdP metadata. If it is not given, the default IdP metadata
           is /conf/idp-metadata.xml.
           
       --idpMetadata path
           The path to the IdP metadata. If it is not given, the default IdP metadata
           is /conf/idp-metadata.xml.
           
       -p path
            The path to the pluggable portion. If it is not given, the default plugin
            is /plugins/ddf-plugins-1.0-SNAPSHOT.jar.
    
       --plugins path
            The path to the pluggable portion. If it is not given, the default plugin
            is /plugins/ddf-plugins-1.0-SNAPSHOT.jar.
```


> NOTE
> 
> In order for the test kit to execute properly, you must configure both the test kit's and your IdP's/SP's metadata, as well as implement plugins
for the user-handled portions of SAML profiles. See "Metadata" and "Plugins" for instructions.

### Metadata
* If testing an IdP:
  * Provide your IdP's metadata file path to the `samlconf` script using `-i` or `--idpMetadata`.
  * Configure your IdP with the test kit's SP metadata from
  `<PATH_TO_PROJECT>/distribution/command-line/src/main/resources/test-sp-metadata.xml`
  or `samlconf-1.0-SNAPSHOT/conf/test-sp-metadata.xml` from the distribution.
  
* **TODO** If testing an SP:
  * Provide your SP's metadata file path to the `samlconf` script using `-s` or `--spMetadata`.
  * Configure your SP with the test kit's IdP metadata from
    `<PATH_TO_PROJECT>/distribution/command-line/src/main/resources/test-idp-metadata.xml`
    or `samlconf-1.0-SNAPSHOT/conf/test-idp-metadata.xml` from the distribution.
   
### Plugins
**TODO** *describe how to implement plugins*

* Provide your plugins directory to the `samlconf` script using `-p` or `--plugins`.

### Docker
To build a docker image, execute `gradle build docker`. 

> NOTE
>
> Docker is used exclusively for our Jenkins builds.

## Steps to Test DDF's IDP
* Start DDF
* Copy the contents of `test-sp-metadata.xml` to `AdminConsole -> Security -> Configuration -> IdPServer -> SP Metadata`.
* If not on localhost, copy DDF's IDP metadata from `https://<hostname>:<port>/services/idp/login/metadata` 
to a file and pass that file to the `samlconf` script using `-i` or `--idpMetadata`.
* Run `samlconf`.

## Steps to Test DDF's SP
**TODO** * Start DDF
* Copy the contents of `test-idp-metadata.xml` to `AdminConsole -> Security -> Configuration -> IdPClient -> IdP Metadata`.
* If not on localhost, copy DDF's SP metadata from `https://<hostname>:<port>/services/saml/sso/metadata` 
to a file and pass that file to the `samlconf` script using `-s` or `--spMetadata`.
* Run `samlconf`.

## Project Structure
This section will briefly talk about the project structure.

### test
This module contains all the test related modules: `idp`, `sp`, and `common`.

#### idp
This module will contain all tests being written against a SAML IdP. The `src` directory of the module is organized by the SAML specification as follows:
* Package: Based on Profile (i.e. WebSSO, Single Logout)
  * Class: Based on Binding (i.e. POST, REDIRECT, ARTIFACT)
* Class: Based on Metadata

#### sp
This module will contain all tests being written against a SAML SP. The src directory of the module is organized identically to the idp module.

#### common
This module contains all the classes relating to utility for and verification of the test classes.

### library
This module contains an assortment of Java classes that have been copied over from DDF to support operations that shouldn't be handled by the test code; i.e. signature validation using x509 certificates.

### plugins
This module contains the API and provider-specific plugin implementations
needed to interact with IdPs/SPs.

#### ddf-plugins
This module contains the ServiceProvider plugins that are used to connect with
a DDF IdP. It should also be used as the model for building plugins for connecting
with other IdPs for compliance testing. The generated jar file from this module
needs to be installed to a deployment directory of the user's choosing and then
referred to by system property when running tests.

e.g. If the ServiceProvider plugin jar(s) are copied to `/home/saml-conform/deploy`
then the tests should be invoked with `-Dsaml.plugin.deployDir=/home/saml-conform/deploy`.

### distribution
This module is the projects full package deployment consisting of: `command-line`, `docker`, and `suites`.

#### command-line
todo: check and elaborate on this&rarr; This module contains all the runtime elements including scripts, jars, and configurations.

#### docker
This module contains the logic for building a docker image.
To build this module you must run the docker task by executing `gradle build docker`.

#### suites
This module contains the test suites.

## TODO:
- Further determine good directory structure (this will happen over time as we add more tests)
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