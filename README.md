# SAML Conformance Test Kit
This project is intended to be a set of blackbox tests that verify the conformance of an IdP/SP to the SAML Spec.
It is currently a prototype being actively developed.

FICAM: https://www.idmanagement.gov/wp-content/uploads/sites/1171/uploads/SAML2_1.0.2_Functional_Reqs.pdf

SAML: https://wiki.oasis-open.org/security/FrontPage

ECP: http://docs.oasis-open.org/security/saml/Post2.0/saml-ecp/v2.0/saml-ecp-v2.0.html

## Setup
To build the project:

    gradlew build

The `distribution/command-line` module will contain a full package of the deployment after the build.

### Running Test Script
Upon a successful build, tests can be run with the `samlconf` script found in:
    
    distribution/command-line/build/install/samlconf/bin/samlconf

The `samlconf` script may take the following parameters:

```
NAME
       samlconf - Runs the SAML Conformance Tests against an IdP or an SP

SYNOPSIS
       samlconf [-i path] [--idpMetadata path]
           [-p path] [--plugins path] 

DESCRIPTION
       Runs the SAML Conformance Tests which tests the compliance of an IdP and/or an SP
       with the SAML Specifications. If a compliance issue is identified, a 
       SAMLConformanceException will be thrown with an explanation of the error and a direct
       quote from the specification. All of the parameters are optional and if they are 
       not provided, the default values will use DDF's parameters. All parameters must 
       be given one time.

OPTIONS
       -i | --idpMetadata path
            The path to the IdP metadata. If it is not given, the default IdP metadata
            is /conf/idp-metadata.xml.
                  
       -d | --debug
           Sets the log level to debug.
           
       -p | --plugins path
            The path to the custom, server-specific plugin implementations. If it is not given, 
            the default plugin directory is /plugins.
```


> NOTE
> 
> In order for the test kit to execute properly, you must configure both the test kit's and your IdP's/SP's metadata, as well as implement plugins
for the user-handled portions of SAML profiles. See "Metadata" and "Plugins" for instructions.

### Formatting
If during development the build fails due to `format violations` run the following command to format:

    gradlew spotlessApply

### Metadata
* If testing an IdP:
  * Provide your IdP's metadata file path to the `samlconf` script using `-i` or `--idpMetadata`.
  * Configure your IdP with the test kit's SP metadata from
  `distribution/command-line/build/install/samlconf/conf/samlconf-sp-metadata.xml`
  or `samlconf-1.0-SNAPSHOT/conf/test-sp-metadata.xml` from the distribution.
   
### Plugins
**TODO** *describe how to implement plugins*

* Provide your plugins directory to the `samlconf` script using `-p` or `--plugins`.

### Docker
To build a docker image, execute `gradlew build docker`. 

> NOTE
>
> Docker is used exclusively for our Jenkins builds.

## Steps to Test DDF's IDP
* Start DDF
* Copy the contents of `samlconf-sp-metadata.xml` to `AdminConsole -> Security -> Configuration -> IdPServer -> SP Metadata`.
* If not on localhost, copy DDF's IDP metadata from `https://<hostname>:<port>/services/idp/login/metadata` 
to a file and pass that file to the `samlconf` script using `-i` or `--idpMetadata`.
* Run `samlconf`.

## Steps to Test DDF's SP
**TODO** * Start DDF
* Copy the contents of `samlconf-idp-metadata.xml` to `AdminConsole -> Security -> Configuration -> IdPClient -> IdP Metadata`.
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
To build this module you must run the docker task by executing `gradlew build docker`.

#### suites
This module contains the test suites.