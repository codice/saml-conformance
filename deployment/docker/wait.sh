#!/bin/bash

# Override the ddf profile to wait for by passing in DDF_PROFILE env var
_target_profile=${TARGET_PROFILE:="minimum"}
# Override the default hostname for the system under test by passing in SUT_HOST
_sut_host=${SUT_HOST:="ddf"}
# Override the default port for the system under test by passing in SUT_PORT
_sut_port=${SUT_PORT:="8993"}
# Override the context used to retrieve the idp-metadata from the system under test by passing in SUT_METADATA
_sut_idp_metadata=${SUT_METADATA:="services/idp/login/metadata"}

_sut_ddf_implementation="/samlconf/implementations/ddf"

_target_feature="security-idp"

set -e

_target_feature_cmd=$(curl -s -k -i -X GET "https://${_sut_host}:${_sut_port}/admin/jolokia/exec/org.apache.karaf:type=feature,name=root/infoFeature(java.lang.String)/profile-${_target_feature}" | grep -i '"Installed":true' | wc -l)
_idp_metadata_cmd=$(curl -s -k -i -X GET "https://${_sut_host}:${_sut_port}/${_sut_idp_metadata}" | grep -i EntityDescriptor | wc -l)

>&2 echo "SAML Conformance is waiting for DDF to start"
>&2 echo "DDF is NOT up - sleeping for a minute initially"
sleep 1m

while [ ${_target_feature_cmd} -ne 1 ] && [ ${_idp_metadata_cmd} -ne 1 ]
do
    >&2 echo "DDF is NOT up - sleeping for 10 seconds"
    sleep 10s
    _target_feature_cmd=$(curl -s -k -i -X GET "https://${_sut_host}:${_sut_port}/admin/jolokia/exec/org.apache.karaf:type=feature,name=root/infoFeature(java.lang.String)/profile-${_target_feature}" | grep -i '"Installed":true' | wc -l)
    _idp_metadata_cmd=$(curl -s -k -i -X GET "https://${_sut_host}:${_sut_port}/${_sut_idp_metadata}" | grep -i EntityDescriptor | wc -l)
done

>&2 echo "Getting idp-metadata from DDF"
curl -LsSk "https://${_sut_host}:${_sut_port}/${_sut_idp_metadata}" -o "${_sut_ddf_implementation}/ddf-idp-metadata.xml"

>&2 echo "DDF is up - executing command"
exec ./samlconf/bin/samlconf -i ${_sut_ddf_implementation} -e
