package org.codice.ckt

import us.jimschubert.kopper.Parser

const val distroDir = "/distribution/command-line/target/command-line-1.0-SNAPSHOT-bin"

fun main(args: Array<String>) {
    val parser = Parser()
    parser.setName("SAML CKT")
    parser.setApplicationDescription("SAML Conformance Test Kit")

    parser.option("i",
            listOf("idpMetadata"),
            description = "Path to the idp metadata")

    parser.option("p",
            listOf("plugins"),
            description = "Path to the plugins directory")

    val arguments = parser.parse(args)

    val idpMetadata = arguments.option("i")
            ?: "${System.getProperty("user.dir")}$distroDir/conf/idp-metadata.xml"
    val pluginDir = arguments.option("p")
            ?: "${System.getProperty("user.dir")}$distroDir/plugins"

    System.setProperty("idp.metadata", idpMetadata)
    System.setProperty("saml.plugin.deployDir", pluginDir)

    org.junit.runner.JUnitCore.main("org.codice.compliance.tests.suites.BasicTestsSuite")
}