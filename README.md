# SAML Conformance Test Kit
This project is intended to be a set of blackbox tests that verify the conformance of an IdP/SP to the SAML Spec.
It is currently a prototype being actively developed.

## Setup
To build the project:

    gradlew build

The `deployment/distribution` module will contain a full package of the deployment after the build.

### Running Test Script
Upon a successful build, tests can be run with the `samlconf` script found in:
    
    deployment/distribution/build/install/samlconf/bin/samlconf

The `samlconf` script may take the following parameters:

    NAME
           samlconf - Runs the SAML Conformance Tests against an IdP or an SP
    
    SYNOPSIS
           samlconf [-i path] [--implementation path]
    
    DESCRIPTION
           Runs the SAML Conformance Tests which tests the compliance of an IdP and/or an SP
           with the SAML Specifications. If a compliance issue is identified, a 
           SAMLConformanceException will be thrown with an explanation of the error and a direct
           quote from the specification. All of the parameters are optional and if they are 
           not provided, the default values will use DDF's parameters. All parameters must 
           be given one time.
    
    OPTIONS
           -i | --implementation path
                The path to the custom, server-specific implementation, including its plugins and metadata. If it is not given, 
                the default implementation directory is /implementations/samlconf-ddf-impl.
                      
           -d | --debug
               Sets the log level to debug.

           -e | --error
               Run tests that expect errors.


> NOTE
> 
> In order for the test kit to execute properly, you must configure both the test kit's and your IdP's/SP's metadata, as well as implement plugins
for the user-handled portions of SAML profiles. See [Metadata](#metadata) and [Implementations](#implementations) for instructions.

### Formatting
If during development the build fails due to `format violations` run the following command to format:

    gradlew spotlessApply

### Metadata
* If testing an IdP:
  * Provide your IdP's metadata to the `samlconf` script by including it in the directory pointed to by
   `-i` or `--implementations`.
  * Configure your IdP with the test kit's SP metadata from
  `deployment/distribution/build/install/samlconf/conf/samlconf-sp-metadata.xml`
  or `samlconf-1.0-SNAPSHOT/conf/samlconf-sp-metadata.xml` from the distribution.
   
### How to Run Against a Specific Implementation
This test kit can already be run against [Keycloak](#samlconf-keycloak-impl) and [DDF](#samlconf-ddf-impl) SAML IdP implementations.
If you're wanting to run the test kit against a different SAML IdP implementation, you will have to follow the below steps.

* Implement a plugin jar for the implementation
    * Write a Java or Kotlin class that implements `IdpSSOResponder`. See that interface for details.
    * Package that file into a jar
* Place the above jar and the IdP's metadata into a directory. Then that directory should be
referred to by system property when running tests. (See [Running Test Script](#running_test_script]))

### Docker
To build a docker image, execute `gradlew build docker`. 

> NOTE
>
> Docker is used exclusively for our Jenkins builds.

## Project Structure
This section will briefly talk about the project structure.

### ctk
This module contains all the test related modules: `idp` and `common`.

#### idp
This module will contain all tests being written against a SAML IdP. The `src` directory of the module is organized by the SAML specification as follows:

* Package: Based on Profile (i.e. WebSSO, Single Logout)
  * Class: Based on Binding (i.e. POST, REDIRECT, ARTIFACT)
* Class: Based on Metadata

This [coverage](ctk/idp/coverage) directory is used to track which sections of each SAML specification are covered by these tests:

#### common
This module contains all the classes relating to utility for and verification of the test classes.

> NOTE 
>
> Schema verification is run before other tests and verifications.

### library
This module contains an assortment of Java classes that have been copied over from DDF to support operations that shouldn't be handled by the test code; i.e. signature validation using x509 certificates.

### external
This module contains anything related to a specific SAML implementing product.

#### api
This module contains the API that must be implemented for a SAML product in order to run this test kit against that product.

#### implementations
This module contains implementations of the API for specific SAML products. See [How to Run Against a Specific Implementation](#how-to-run-against-a-specific-implementation) for details.

##### samlconf-ddf-impl
Plugin and idp-metadata.xml for the ddf implementation of IdP. See the README in this directory for details.

##### samlconf-keycloak-impl
Plugin and idp-metadata.xml for the Keycloak implementation of IdP. See the README in this directory for details.

### deployment
This module is the project's full package deployment.

#### distribution
This module contains all the runtime elements including scripts, jars, and configurations.

#### docker
This module contains the logic for building a docker image.
To build this module you must run the docker task by executing `gradlew build docker`.

#### suites
This module contains the test suites.

## References
FICAM: https://www.idmanagement.gov/wp-content/uploads/sites/1171/uploads/SAML2_1.0.2_Functional_Reqs.pdf

SAML: https://wiki.oasis-open.org/security/FrontPage

ECP: http://docs.oasis-open.org/security/saml/Post2.0/saml-ecp/v2.0/saml-ecp-v2.0.html
