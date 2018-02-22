#!/usr/bin/env bash

java -cp "../lib/*" $1 org.junit.runner.JUnitCore org.codice.compliance.tests.PostLoginTest