#!/bin/bash

# Override the ddf profile to wait for by passing in DDF_PROFILE env var
_target_profile=${TARGET_PROFILE:="standard"}
# Override the default hostname for the system under test by passing in SUT_HOST
_sut_host=${SUT_HOST:="ddf"}
# Override the default port for the system under test by passing in SUT_PORT
_sut_port=${SUT_PORT:="8993"}
# Override the context used to retrieve the idp-metadata from the system under test by passing in SUT_METADATA
_sut_idp_metadata=${SUT_METADATA:="services/idp/login/metadata"}

_sut_idp_metadata_file="/samlconf/conf/idp-metadata.xml"

set -e

cmd=$(curl -s -k -i -X GET "https://${_sut_host}:${_sut_port}/admin/jolokia/exec/org.apache.karaf:type=feature,name=root/infoFeature(java.lang.String)/profile-${_target_profile}" | grep -i '"Installed":true' | wc -l)

# Sleeping for 30 seconds to give DDF time to start up before hitting jolokia endpoint
>&2 echo "SAML CKT WAITING FOR DDF"
>&2 echo "DDF is NOT up - sleeping for a minute initially"
sleep 1m

while [ ${cmd} -ne 1 ]
do
    >&2 echo "DDF is NOT up - sleeping for 10 seconds"
    sleep 10s
    cmd=$(curl -s -k -i -X GET "https://${_sut_host}:${_sut_port}/admin/jolokia/exec/org.apache.karaf:type=feature,name=root/infoFeature(java.lang.String)/profile-${_target_profile}" | grep -i '"Installed":true' | wc -l)
done

>&2 echo "Getting idp-metadata from DDF"
curl -LsSk "https://${_sut_host}:${_sut_port}/${_sut_idp_metadata}" -o ${_sut_idp_metadata_file}

>&2 echo "DDF is up - executing command"
exec /samlconf/bin/samltest.sh -Didp.metadata=${_sut_idp_metadata_file} -Dsaml.plugin.deployDir=/samlconf/plugins
