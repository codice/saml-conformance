package org.codice.ckt

import org.codice.compliance.IDP_METADATA_PROPERTY
import org.codice.compliance.PLUGIN_DIR_PROPERTY
import org.codice.compliance.TEST_SP_METADATA_PROPERTY
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

    System.setProperty(IDP_METADATA_PROPERTY, idpMetadata)
    System.setProperty(TEST_SP_METADATA_PROPERTY, "$samlDist/conf/test-sp-metadata.xml")
    System.setProperty(PLUGIN_DIR_PROPERTY, pluginDir)

    org.junit.runner.JUnitCore.main("org.codice.compliance.tests.suites.BasicTestsSuite")
}
