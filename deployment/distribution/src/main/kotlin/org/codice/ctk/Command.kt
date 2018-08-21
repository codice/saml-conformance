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
import org.codice.compliance.RUN_DDF_PROFILE
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
import org.fusesource.jansi.Ansi.ansi
import org.junit.platform.engine.TestExecutionResult
import org.junit.platform.engine.discovery.DiscoverySelectors.selectClass
import org.junit.platform.launcher.TestExecutionListener
import org.junit.platform.launcher.TestIdentifier
import org.junit.platform.launcher.TestPlan
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder
import org.junit.platform.launcher.core.LauncherFactory
import org.junit.platform.launcher.listeners.SummaryGeneratingListener
import us.jimschubert.kopper.Parser
import java.io.File
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

    val parser = createParser()
    val arguments = parser.parse(args)

    val implementationPath = arguments.option("i")
            ?: "$samlDist${File.separator}$DEFAULT_IMPLEMENTATION_PATH"
    val userLogin = arguments.option("i") ?: "admin:admin"

    System.setProperty(IMPLEMENTATION_PATH, implementationPath)
    System.setProperty(USER_LOGIN, userLogin)
    System.setProperty(TEST_SP_METADATA_PROPERTY, "$samlDist${File.separator}conf" +
            "${File.separator}samlconf-sp-metadata.xml")
    System.setProperty(LENIENT_ERROR_VERIFICATION, arguments.flag("l").toString())
    System.setProperty(RUN_DDF_PROFILE, arguments.flag("ddf").toString())

    if (arguments.flag("debug")) {
        Log.logLevel = LogLevel.DEBUG
    } else {
        Log.logLevel = LogLevel.INFO
    }

    launchTests()
}

private fun createParser(): Parser {
    return Parser().apply {
        setName("SAML CTK")
        setApplicationDescription("SAML Conformance Test Kit")

        option("i", description = "Path to the implementation to be tested")
        option("u", description = "User used to login in the format username:password.")

        flag("debug", description = "Turn on debug logs.")
        flag("ddf", description = """Run the DDF profile. If provided runs the optional
            SAML V2.0 StandardSpecification rules required by DDF.""")
        flag("l", description = """When an error occurs, the SAML V2.0 Standard
            Specification requires an IdP to respond with a 200 HTTP status code and a valid SAML
            response containing an error <StatusCode>. If the -l flag is given, this test kit will
            allow HTTP error status codes as a valid error response.""")
    }
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
        registerTestExecutionListeners(summaryGeneratingListener, TestNameListener())
    }.execute(request)

    PrintWriter(System.out).use { printer ->

        summaryGeneratingListener.summary.printFailuresTo(printer)
        summaryGeneratingListener.summary.printTo(printer)

        if (summaryGeneratingListener.summary.totalFailureCount > 0) {
            System.out.println(ansi().fgRed().a("TESTS FAILED").reset())
            System.exit(1)
        }

        printer.println(ansi().fgGreen().a("TESTS PASSED").reset())
    }
}

private class TestNameListener : TestExecutionListener {
    override fun testPlanExecutionStarted(testPlan: TestPlan?) {
        System.out.apply {
            println()
            println("----------------------------------")
            println("SAML Conformance Test Kit Starting")
            println("----------------------------------")
        }
    }

    override fun executionFinished(
        testIdentifier: TestIdentifier,
        testExecutionResult: TestExecutionResult
    ) {
        if (testIdentifier.isTest)
            System.out.println(
                    "${testIdentifier.displayName} ${getResultDisplay(testExecutionResult.status)}")
    }

    private fun getResultDisplay(status: TestExecutionResult.Status): Any {
        return when (status) {
            TestExecutionResult.Status.SUCCESSFUL -> ansi().fgGreen().a(status.name).reset()
            TestExecutionResult.Status.FAILED -> ansi().fgRed().a(status.name).reset()
            else -> status.name
        }
    }
}
