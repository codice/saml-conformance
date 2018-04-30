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
import org.codice.compliance.IMPLEMENTATION_PATH
import org.codice.compliance.TEST_SP_METADATA_PROPERTY
import org.codice.compliance.web.sso.PostSSOTest
import org.codice.compliance.web.sso.RedirectSSOTest
import org.codice.ctk.Runner.Companion.BASIC_TESTS
import org.junit.platform.engine.discovery.DiscoverySelectors.selectClass
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder
import org.junit.platform.launcher.core.LauncherFactory
import org.junit.platform.launcher.listeners.SummaryGeneratingListener
import us.jimschubert.kopper.ArgumentCollection
import us.jimschubert.kopper.Parser
import java.io.PrintWriter

private class Runner {
    companion object {
        val BASIC_TESTS = arrayOf(selectClass(PostSSOTest::class.java),
            selectClass(RedirectSSOTest::class.java))
//        val ERROR_TESTS = arrayOf(selectClass(RedirectSSOErrorTest::class.java),
//            selectClass(PostSSOErrorTest::class.java))
    }
}

fun main(args: Array<String>) {
    val samlDist = System.getProperty("app.home")
    requireNotNull(samlDist) { "app.home System property must be set" }

    val parser = Parser()
    parser.setName("SAML CTK")
    parser.setApplicationDescription("SAML Conformance Test Kit")

    parser.option("i",
        listOf("implementation"),
        description = "Path to the implementation to be tested")

    parser.flag("d",
        listOf("debug"),
        description = "Turn on debug logs.")

    parser.flag("e",
        listOf("error"),
        description = "Run tests that expect errors.")

    val arguments = parser.parse(args)

    val implementationPath = arguments.option("i")
        ?: "$samlDist/implementations/ddf"

    System.setProperty(IMPLEMENTATION_PATH, implementationPath)
    System.setProperty(TEST_SP_METADATA_PROPERTY, "$samlDist/conf/samlconf-sp-metadata.xml")

    if (arguments.flag("d")) {
        Log.logLevel = LogLevel.DEBUG
    } else {
        Log.logLevel = LogLevel.INFO
    }

    launchTests(arguments)
}

@Suppress("SpreadOperator")
private fun launchTests(arguments: ArgumentCollection) {
    val request = LauncherDiscoveryRequestBuilder.request().selectors(*BASIC_TESTS).apply {
//        if (arguments.flag("e")) {
//            selectors(*ERROR_TESTS)
//        }
    }.build()

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
