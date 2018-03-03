#!/bin/bash

set -e

cmd=$(curl -s -k -i -X GET 'https://localhost:8993/admin/jolokia/exec/org.apache.karaf:type=feature,name=root/infoFeature(java.lang.String)/profile-standard' | grep -i '"Installed":true' | wc -l)

# Sleeping for 30 seconds to give DDF time to start up before hitting jolokia endpoint
>&2 echo "SAML CKT WAITING FOR DDF"
>&2 echo "DDF is NOT up - sleeping for a minute initially"
sleep 1m

while [ ${cmd} -ne 1 ]
do
    >&2 echo "DDF is NOT up - sleeping for 10 seconds"
    sleep 10s
done

>&2 echo "DDF is up - executing command"
exec /samlconf/bin/samltest.sh -Didp.metadata=/samlconf/conf/idp-metadata.xml -Dsaml.plugin.deployDir=/samlconf/plugins