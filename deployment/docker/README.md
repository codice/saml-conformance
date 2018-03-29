# SAMLconf in Docker

This image can execute a test against a remote host. It is used to run the conformance test against DDF.

To use, run `docker run -it -e SUT_HOST=<target_hostname> -e SUT_PORT=<target_port> codice/samlconf`

# Advanced

## Retrieve IdP Metadata Automatically

This image can automatically retrieve IdP metadata from a remote system if it is supported

To change the default location that IdP metadata is retrieved from set the following environment variables

`SUT_HOST`: hostname of the system under test (default: `ddf`)
`SUT_PORT`: port for the system under test (default: `8993`)
`SUT_METADATA`: context to retrieve metadata from (default: `services/idp/login/metadata`)

## Specify Alternate DDF profile

During startup of this image, the target system is polled to check if it is ready (assumes a ddf currently).
This is done by checking if the desired install profile on the target system is ready. To change the default install profile to expect:

`TARGET_PROFILE` specify an alternate install profile, like `minimum`, `full`, `standard` (default: `standard`)
