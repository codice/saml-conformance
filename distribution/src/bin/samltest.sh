#!/usr/bin/env bash

BIN_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
DEPLOY_DIR=$BIN_DIR/..
LIB_DIR=$DEPLOY_DIR/lib
PLUGIN_DIR=$DEPLOY_DIR/plugins
CONF_DIR=$DEPLOY_DIR/conf
IDP_META=$CONF_DIR/idp-metadata.xml
SP_META=$CONF_DIR/test-sp-metadata.xml

java -cp "$LIB_DIR/*" \
  -Didp.metadata=$IDP_META \
  -Dsp.metadata=$SP_META \
  -Dsaml.plugin.deployDir=$PLUGIN_DIR \
  org.junit.runner.JUnitCore org.codice.compliance.tests.suites.BasicTestsSuite
