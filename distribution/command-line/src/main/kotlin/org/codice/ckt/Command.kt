package org.codice.ckt

import us.jimschubert.kopper.Parser

fun main(args: Array<String>) {
    val parser = Parser()
    parser.setName("SAML CKT")
    parser.setApplicationDescription("SAML Conformance Test Kit")

    parser.option("i",
            listOf("idpMetadata"),
            description = "Path to the idp metadata",
            default = System.getProperty("user.dir") + "/distribution/command-line/target/command-line-1.0-SNAPSHOT-bin/conf/idp-metadata.xml")

    parser.option("p",
            listOf("plugins"),
            description = "Path to the plugins directory",
            default = System.getProperty("user.dir") + "/distribution/command-line/target/command-line-1.0-SNAPSHOT-bin/plugins")

    val arguments = parser.parse(args)
    System.setProperty("idp.metadata", "${arguments.option("i")}")
    System.setProperty("saml.plugin.deployDir", "${arguments.option("p")}")

    org.junit.runner.JUnitCore.main("org.codice.compliance.tests.suites.BasicTestsSuite")
}