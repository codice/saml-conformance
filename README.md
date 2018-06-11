# SAML Conformance Test Kit
This project is intended to be a set of blackbox tests that verify the conformance of an IdP to the SAML V2.0 Standard Specification.
It is currently a prototype being actively developed.

> NOTE
> 
> - This test kit only supports SAML Version 2.0. All other version are not supported.
>
> - It does not support proxying.
>
> - Only MUSTs from the specification are tested, currently.
> 
> - This test kit only support `RSAwithSHA1` and `DSAwithSHA1` algorithms for Redirect and XML Signatures.

## Building
To build the project:

    gradlew build

After the build, the full package of the deployment will be located at `deployment/distribution/build/install/samlconf`.

### Formatting
If during development the build fails due to `format violations` run the following command to format:

    gradlew spotlessApply

### Docker
To build a docker image, execute `gradlew build docker`.

> NOTE
>
> Docker is used exclusively for our Jenkins builds.

## Running

### Setup for a Specific Implementation
> NOTE
>
> This test kit includes built-in support for [Keycloak](external/implementations/samlconf-keycloak-impl/README.md) and [Distributed Data Framework](external/implementations/samlconf-ddf-impl/README.md) (DDF) SAML Identity Providers.
> Steps 1 and 2 have been completed and packaged under `implementations` in the distribution.
> Steps 3-5 for those specific providers are documented in more detail under the corresponding README's.

1. Implement a plugin jar for the implementation
    * Write a Java or Kotlin class that implements [IdpSSOResponder](external/api/src/main/java/org/codice/compliance/saml/plugin/IdpSSOResponder.java).
    * Package that file into a jar
2. Place the jar from step 1 and the IdP's metadata into a directory.
3. Setup your IdP.
4. Configure your IdP with the test kit's SP metadata from `deployment/distribution/build/install/samlconf/conf/samlconf-sp-metadata.xml`.
5. The directory from step 2 should be referred to with the `-i` option when running tests. (See [Run The Tests](#run_the_tests]))

### Run the tests
After a successful gradle build, tests can be run with the generated `samlconf` script:
    
- `cd deployment/distribution/build/install/samlconf/bin`
- `./samlconf`

The `samlconf` script may take the following parameters:

    NAME
           samlconf - Runs the SAML Conformance Tests against an IdP
    
    SYNOPSIS
           samlconf [arguments ...]
    
    DESCRIPTION
           Runs the SAML Conformance Tests which test the compliance of an IdP
           with the SAML Specifications. If a compliance issue is identified, a
           SAMLComplianceException will be thrown with an explanation of the error and a direct
           quote from the specification. Tests will not run if the corresponding
           endpoints do not exist in the IdP's metadata. All of the parameters
           are optional and if they are not provided, the default values will use DDF's parameters.
    
    OPTIONS
           -i path
                The path to the directory containing the implementation's plugin and metadata.
                The default value is `/implementations/ddf`.
                      
           -d
                Boolean for whether or not to enable debug mode which enables more logging.
                The default value is false.

           -l
                When an error occurs, the SAML V2.0 Standard Specification requires an IdP to 
                respond with a 200 HTTP status code and a valid SAML response containing an 
                error <StatusCode>.
                If the -l flag is given, this test kit will allow HTTP error status codes as 
                a valid error response (i.e. 400's and 500's).
                If it is not given, this test kit will only verify that a valid SAML error 
                response is returned.

## Project Structure
This section will briefly talk about the project structure.

### ctk
This module contains all the test related modules.

#### idp
This module will contain all tests being written against a SAML IdP. The `src` directory of the module is organized by the SAML specification as follows:

* Package: Based on Profile (i.e. WebSSO, Single Logout)
  * Class: Based on Binding (i.e. POST, REDIRECT, ARTIFACT)

The [coverage](ctk/idp/coverage) directory is used to track which sections of each SAML specification are covered by these tests. It also includes a list of MUSTs that are not tested and justification for each.

#### common
This module contains all the classes relating to utility for and verification of the test classes.

> NOTE 
>
> Schema verification is run before other tests and verifications.

### library
This module contains an assortment of Java classes that have been copied over from DDF to support operations that shouldn't be handled by the test code; i.e. signature validation using x509 certificates.

### external
This module contains anything related to a specific SAML implementing product.

#### samlconf-plugins-api
This module contains the API that must be implemented for a SAML product in order to run this test kit against that product.

#### implementations
This module contains implementations of the API for specific SAML products.

##### samlconf-ddf-impl
Plugin and IdP metadata XML for the ddf implementation of IdP. See the [DDF](external/implementations/samlconf-ddf-impl/README.md) in this directory for details.

##### samlconf-keycloak-impl
Plugin and IdP metadata XML for the Keycloak implementation of IdP. See the [Keycloak](external/implementations/samlconf-keycloak-impl/README.md) in this directory for details.

### deployment
This module is the project's full package deployment.

#### distribution
This module contains all the runtime elements including scripts, jars, and configurations.

#### docker
This module contains the logic for building a docker image.
To build this module you must run the docker task by executing `gradlew build docker`.

## References
FICAM: https://www.idmanagement.gov/wp-content/uploads/sites/1171/uploads/SAML2_1.0.2_Functional_Reqs.pdf

SAML: https://wiki.oasis-open.org/security/FrontPage
