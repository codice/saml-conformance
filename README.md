# SAML Conformance Test Kit
This project is intended to be a set of blackbox tests that verify the conformance of an IdP/SP to the SAML Spec.
It is currently a prototype being actively developed.

FICAM: https://www.idmanagement.gov/wp-content/uploads/sites/1171/uploads/SAML2_1.0.2_Functional_Reqs.pdf

SAML: https://wiki.oasis-open.org/security/FrontPage

ECP: http://docs.oasis-open.org/security/saml/Post2.0/saml-ecp/v2.0/saml-ecp-v2.0.html

## Setup
To build the project, execute `mvn clean install -nsu` at the project root.
The `distribution` module will contain a full package of the deployment after the build.
Tests can be run with the script:

`<PATH_TO_PROJECT>/distribution/command-line/target/command-line-<VERSION>-bin/bin/samltest.sh`.

>NOTE
>
>In order for the test kit to execute properly, you must configure both
the test kit's and your IdP's/SP's metadata, as well as implement plugins
for the user-handled portions of SAML profiles. See "Metadata" and "Plugins" for instructions.

### Metadata
* If testing an IdP:
  * **TODO** *This requires the user to rebuild and is not an optimal
  configuration solution. A solution that works with a pre-built artifact
  should be found.* Configure the test kit with your IdP's metadata by updating
  `<PATH_TO_PROJECT>/distribution/command-line/src/main/resources/idp-metadata.xml`
  prior to building.
  * Configure your IdP with the test kit's metadata from
  `<PATH_TO_PROJECT>/distribution/command-line/src/main/resources/test-sp-metadata.xml`.
  
* **TODO** If testing an SP:
  * Place your SP's metadata into `sp-metadata.xml` under `<PATH_TO_PROJECT>/distribution/command-line/src/main/resources`.
  * Copy `test-idp-metadata.xml` under `<PATH_TO_PROJECT>/distribution/command-line/src/main/resources` into your SP.
   
### Plugins
**TODO** describe how to implement plugins

**TODO** *This requires the user to rebuild and is not an optimal configuration
solution. A solution that works with a pre-built artifact should be found.*
Place your plugins in `<PATH_TO_PROJECT>/distribution/command-line/target/command-line-<VERSION>-bin/plugins`.

### Docker
To build a docker image, add `-P docker` to the build command. To run it, run:

`docker run --rm -it -v <IDP_METADATA_PATH>:/samlconf/conf/idp-metadata.xml --add-host "<HOST_NAME>:<IP>" codice/samlconf`

Where 
* `<IDP_METADATA_PATH>` is the path to the file containing the idp's metadata
(anywhere on your local machine ex: `/tmp/idp.xml`)
* `<HOST_NAME>` is the hostname the IdP is running on (for DDF, DDF's hostname)
* `<IP>` is the machine's IP address

>NOTE
>
>To run the tests using the `docker-compose.yml` file, run `docker-compose up`
in the `/docker` module.

>NOTE
>
>If building throws a `Connect to localhost:2375 [localhost/127.0.0.1, localhost/0:0:0:0:0:0:0:1] failed: Connection refused`
error, go into docker settings &rarr; general &rarr; enable `Expose daemon to tcp://localhost:2375 without TLS`.

### Running Tests in IDE

Edit the run configuration of your tests to include the vm variables:

* `-Dsaml.plugin.deployDir=<PATH_TO_PROJECT>/distribution/command-line/target/command-line-<VERSION>-bin/plugins`
* `-Didp.metadata=<PATH_TO_PROJECT>/distribution/command-line/target/command-line-<VERSION>-bin/conf/idp-metadata.xml`
* todo `-Didp.metadata=<PATH_TO_PROJECT>/distribution/command-line/target/command-line-<VERSION>-bin/conf/sp-metadata.xml`

## Steps to Test DDF's IDP
* Boot up DDF
* Copy the contents of `test-sp-metadata.xml` under `...saml-conformance/distribution/command-line/src/main/resources` to `AdminConsole -> Security -> Configuration -> IdPServer -> SP Metadata`.
* If not on localhost, copy DDF's IDP metadata from `https://<hostname>:<port>/services/saml/sso/metadata` to `idp-metadata.xml` under `...saml-conformance/distribution/command-line/src/main/resources`.
* Run the tests through your IDE by setting the vm variables (see "Running Tests in IDE") or by invoking the `...saml-conformance/distribution/command-line/target/command-line-\[VERSION\]-bin/bin/samltest.sh` script.

## Steps to Test DDF's SP
todo

## Project Structure
This section will briefly talk about the project structure.

### test
This module contains all the test related modules: `idp`, `sp`, and `common`.

#### idp
This module will contain all tests being written against a SAML IdP. The src directory of the module is organized by the SAML spec as follows:
* Package: Based on Profile (i.e. WebSSO, Single Logout)
  * Class: Based on Binding (i.e. POST, REDIRECT, ARTIFACT)
* Class: Based on Metadata

#### sp
This module will contain all tests being written against a SAML SP. The src directory of the module is organized identically to the idp module.

#### common
This module contains all the classes relating to utility for and verification of the test classes.

### library
This module contains an assortment of Java classes that have been copied over from DDF to support operations that shouldn't be handled by the test code; i.e. signature validation using x509 certificates.

### ddf-plugins
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
todo: check this&rarr; This module contains the logic for building a docker image.

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