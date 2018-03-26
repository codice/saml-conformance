/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package org.codice.ckt

import de.jupf.staticlog.Log
import de.jupf.staticlog.core.LogLevel
import org.codice.compliance.IDP_METADATA_PROPERTY
import org.codice.compliance.PLUGIN_DIR_PROPERTY
import org.codice.compliance.TEST_SP_METADATA_PROPERTY
import us.jimschubert.kopper.Parser

fun main(args: Array<String>) {
    val samlDist = System.getProperty("app.home")
    requireNotNull(samlDist) { "app.home System property must be set" }

    val parser = Parser()
    parser.setName("SAML CKT")
    parser.setApplicationDescription("SAML Conformance Test Kit")

    parser.option("i",
            listOf("idpMetadata"),
            description = "Path to the idp metadata")

    parser.option("p",
            listOf("plugins"),
            description = "Path to the plugins directory")

    parser.flag("d",
            listOf("debug"),
            description = "Turn on debug logs.")

    val arguments = parser.parse(args)

    val idpMetadata = arguments.option("i")
            ?: "$samlDist/conf/idp-metadata.xml"
    val pluginDir = arguments.option("p")
            ?: "$samlDist/plugins"

    System.setProperty(IDP_METADATA_PROPERTY, idpMetadata)
    System.setProperty(TEST_SP_METADATA_PROPERTY, "$samlDist/conf/test-sp-metadata.xml")
    System.setProperty(PLUGIN_DIR_PROPERTY, pluginDir)

    if (arguments.flag("d")) {
        Log.logLevel = LogLevel.DEBUG
    } else {
        Log.logLevel = LogLevel.INFO
    }
    org.junit.runner.JUnitCore.main("org.codice.compliance.tests.suites.BasicTestsSuite")
}
