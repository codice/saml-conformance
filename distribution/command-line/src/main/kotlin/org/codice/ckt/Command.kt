package org.codice.ckt

import us.jimschubert.kopper.Parser

val samlDist = "${System.getProperty("user.dir")}/.."

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
            ?: "$samlDist/conf/idp-metadata.xml"
    val pluginDir = arguments.option("p")
            ?: "$samlDist/plugins"

    System.setProperty("idp.metadata", idpMetadata)
    System.setProperty("test.sp.metadata", "$samlDist/conf/test-sp-metadata.xml")
    System.setProperty("saml.plugin.deployDir", pluginDir)

    System.out.println("idp.metadata = $idpMetadata")
    System.out.println("test.sp.metadata = $samlDist/conf/test-sp-metadata.xml")
    System.out.println("saml.plugin.deployDir = $pluginDir")

    org.junit.runner.JUnitCore.main("org.codice.compliance.tests.suites.BasicTestsSuite")
}