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
package org.codice.ctk

import de.jupf.staticlog.Log
import de.jupf.staticlog.core.LogLevel
import org.codice.compliance.DEFAULT_IMPLEMENTATION_PATH
import org.codice.compliance.IMPLEMENTATION_PATH
import org.codice.compliance.LENIENT_ERROR_VERIFICATION
import org.codice.compliance.TEST_SP_METADATA_PROPERTY
import org.codice.compliance.USER_LOGIN
import org.codice.compliance.web.slo.PostSLOTest
import org.codice.compliance.web.slo.RedirectSLOTest
import org.codice.compliance.web.slo.error.PostSLOErrorTest
import org.codice.compliance.web.slo.error.RedirectSLOErrorTest
import org.codice.compliance.web.sso.PostSSOTest
import org.codice.compliance.web.sso.RedirectSSOTest
import org.codice.compliance.web.sso.error.PostSSOErrorTest
import org.codice.compliance.web.sso.error.RedirectSSOErrorTest
import org.codice.ctk.Runner.Companion.SLO_BASIC_TESTS
import org.codice.ctk.Runner.Companion.SLO_ERROR_TESTS
import org.codice.ctk.Runner.Companion.SSO_BASIC_TESTS
import org.codice.ctk.Runner.Companion.SSO_ERROR_TESTS
import org.junit.platform.engine.discovery.DiscoverySelectors.selectClass
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder
import org.junit.platform.launcher.core.LauncherFactory
import org.junit.platform.launcher.listeners.SummaryGeneratingListener
import us.jimschubert.kopper.Parser
import java.io.PrintWriter

private class Runner {
    companion object {
        val SSO_BASIC_TESTS = arrayOf(selectClass(PostSSOTest::class.java),
                selectClass(RedirectSSOTest::class.java))
        val SSO_ERROR_TESTS = arrayOf(selectClass(RedirectSSOErrorTest::class.java),
                selectClass(PostSSOErrorTest::class.java))
        val SLO_BASIC_TESTS = arrayOf(selectClass(PostSLOTest::class.java),
                selectClass(RedirectSLOTest::class.java))
        val SLO_ERROR_TESTS = arrayOf(selectClass(PostSLOErrorTest::class.java),
                selectClass(RedirectSLOErrorTest::class.java))
    }
}

fun main(args: Array<String>) {
    val samlDist = System.getProperty("app.home")
    requireNotNull(samlDist) { "app.home System property must be set" }

    val parser = Parser()
    parser.setName("SAML CTK")
    parser.setApplicationDescription("SAML Conformance Test Kit")

    parser.option("i",
            description = "Path to the implementation to be tested")

    parser.option("u",
            description = "User used to login in the format username:password.")

    parser.flag("d",
            description = "Turn on debug logs.")

    parser.flag("l",
            description = """When an error occurs, the SAML V2.0 Standard Specification requires an
                IdP to respond with a 200 HTTP status code and a valid SAML response containing an
                error <StatusCode>. If the -l flag is given, this test kit will allow HTTP error
                status codes as a valid error response.""")

    val arguments = parser.parse(args)

    val implementationPath = arguments.option("i")
            ?: "$samlDist/$DEFAULT_IMPLEMENTATION_PATH"

    val userLogin = arguments.option("i") ?: "admin:admin"

    System.setProperty(IMPLEMENTATION_PATH, implementationPath)
    System.setProperty(USER_LOGIN, userLogin)
    System.setProperty(TEST_SP_METADATA_PROPERTY, "$samlDist/conf/samlconf-sp-metadata.xml")
    System.setProperty(LENIENT_ERROR_VERIFICATION, arguments.flag("l").toString())

    if (arguments.flag("d")) {
        Log.logLevel = LogLevel.DEBUG
    } else {
        Log.logLevel = LogLevel.INFO
    }

    launchTests()
}

@Suppress("SpreadOperator")
private fun launchTests() {
    val request = LauncherDiscoveryRequestBuilder.request()
            .selectors(*SSO_BASIC_TESTS,
                    *SSO_ERROR_TESTS,
                    *SLO_BASIC_TESTS,
                    *SLO_ERROR_TESTS)
            .build()

    val summaryGeneratingListener = SummaryGeneratingListener()
    LauncherFactory.create().apply {
        registerTestExecutionListeners(summaryGeneratingListener)
    }.execute(request)

    PrintWriter(System.out).use { printer ->
        summaryGeneratingListener.summary.printFailuresTo(printer)
        summaryGeneratingListener.summary.printTo(printer)

        if (summaryGeneratingListener.summary.totalFailureCount > 0) {
            System.out.println("TESTS FAILED")
            System.exit(1)
        }

        printer.println("TESTS PASSED")
    }
}
