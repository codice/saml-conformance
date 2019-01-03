/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.ctk

import de.jupf.staticlog.Log
import de.jupf.staticlog.core.LogLevel
import org.codice.compliance.DEFAULT_IMPLEMENTATION_PATH
import org.codice.compliance.IMPLEMENTATION_PATH
import org.codice.compliance.LENIENT_ERROR_VERIFICATION
import org.codice.compliance.QUIET_MODE
import org.codice.compliance.RUN_DDF_PROFILE
import org.codice.compliance.TEST_SP_METADATA_PROPERTY
import org.codice.compliance.USER_LOGIN
import us.jimschubert.kopper.Parser
import java.io.File

@Suppress("StringLiteralDuplication")
fun main(args: Array<String>) {
    val samlDist = System.getProperty("app.home")
    requireNotNull(samlDist) { "app.home system property must be set" }

    val defaultImplPath = "$samlDist${File.separator}$DEFAULT_IMPLEMENTATION_PATH"
    val ctkMetadataPath = "$samlDist${File.separator}conf${File.separator}samlconf-sp-metadata.xml"

    val parser = createParser()
    val arguments = parser.parse(args)

    val implementationPath = arguments.option("i") ?: defaultImplPath
    val userLogin = arguments.option("u") ?: "admin:admin"

    if (arguments.flag("help")) {
        println(parser.printHelp())
        return
    }

    System.setProperty(IMPLEMENTATION_PATH, implementationPath)
    System.setProperty(USER_LOGIN, userLogin)
    System.setProperty(TEST_SP_METADATA_PROPERTY, ctkMetadataPath)
    System.setProperty(LENIENT_ERROR_VERIFICATION, arguments.flag("l").toString())
    System.setProperty(RUN_DDF_PROFILE, arguments.flag("ddf").toString())
    System.setProperty(QUIET_MODE, arguments.flag("q").toString())

    Log.logLevel = if (arguments.flag("debug")) {
        LogLevel.DEBUG
    } else {
        LogLevel.INFO
    }

    TestRunner().launchTests()
}

private fun createParser(): Parser {
    return Parser().apply {
        setName("SamlConf - Runs the SAML Conformance Tests against an IdP")

        flag("ddf",
                longOption = listOf("ddf"),
                description = """Runs the DDF profile. If provided runs the optional SAML V2.0
                    Standard Specification rules required by DDF."""
        )

        flag("debug",
                longOption = listOf("debug"),
                description = """Enables debug mode which enables more logging. This mode is off
                        by default."""
        )

        flag("h",
                longOption = listOf("help"),
                description = "Displays the possible arguments."
        )

        option("i",
                longOption = listOf("implementation"),
                description = """The path to the directory containing the implementation's
                        plugin and metadata. The default value is /implementations/ddf."""
        )

        flag("l",
                longOption = listOf("lenient"),
                description = """When an error occurs, the SAML V2.0 Standard Specification
                        requires an IdP to respond with a 200 HTTP status code and a valid SAML
                        response containing an error <StatusCode>. If the -l flag is given, this
                        test kit will allow HTTP error status codes as a valid error response
                        (i.e. 400's and 500's). If it is not given, this test kit will only verify
                        that a valid SAML error response is returned."""
        )

        flag("q",
                longOption = listOf("quiet"),
                description = """If provided, only displays whether a test or a section passed or
                    failed. Errors will not be printed."""
        )

        option("u",
                longOption = listOf("userLogin"),
                description = """The username and password to use when logging in. The default
                        value is admin:admin."""
        )
    }
}
