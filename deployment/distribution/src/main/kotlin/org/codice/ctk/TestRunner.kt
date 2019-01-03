/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.ctk

import org.codice.compliance.report.Report
import org.codice.compliance.web.slo.PostSLOTest
import org.codice.compliance.web.slo.RedirectSLOTest
import org.codice.compliance.web.slo.error.PostSLOErrorTest
import org.codice.compliance.web.slo.error.RedirectSLOErrorTest
import org.codice.compliance.web.sso.PostSSOTest
import org.codice.compliance.web.sso.RedirectSSOTest
import org.codice.compliance.web.sso.error.PostSSOErrorTest
import org.codice.compliance.web.sso.error.RedirectSSOErrorTest
import org.fusesource.jansi.Ansi
import org.junit.platform.engine.TestExecutionResult
import org.junit.platform.engine.TestExecutionResult.Status.FAILED
import org.junit.platform.engine.TestExecutionResult.Status.SUCCESSFUL
import org.junit.platform.engine.discovery.DiscoverySelectors.selectClass
import org.junit.platform.launcher.TestExecutionListener
import org.junit.platform.launcher.TestIdentifier
import org.junit.platform.launcher.TestPlan
import org.junit.platform.launcher.core.LauncherDiscoveryRequestBuilder
import org.junit.platform.launcher.core.LauncherFactory
import org.junit.platform.launcher.listeners.SummaryGeneratingListener

internal class TestRunner {
    private class Runner {
        companion object {
            val TESTS = arrayOf(
                    selectClass(PostSSOTest::class.java),
                    selectClass(PostSSOErrorTest::class.java),
                    selectClass(PostSLOTest::class.java),
                    selectClass(PostSLOErrorTest::class.java),
                    selectClass(RedirectSSOTest::class.java),
                    selectClass(RedirectSSOErrorTest::class.java),
                    selectClass(RedirectSLOTest::class.java),
                    selectClass(RedirectSLOErrorTest::class.java)
            )
        }
    }

    @Suppress("SpreadOperator")
    internal fun launchTests() {
        val request = LauncherDiscoveryRequestBuilder.request()
                .selectors(*Runner.TESTS)
                .build()

        val summaryGeneratingListener = SummaryGeneratingListener()
        LauncherFactory.create().apply {
            registerTestExecutionListeners(summaryGeneratingListener, TestNameListener())
        }.execute(request)

        Report.writeReport()

        if (Report.hasExceptions()) {
            println(Ansi.ansi().fgRed().a("TESTS FAILED").reset())
            System.exit(1)
        }

        println(Ansi.ansi().fgGreen().a("TESTS PASSED").reset())
    }

    private class TestNameListener : TestExecutionListener {
        override fun testPlanExecutionStarted(testPlan: TestPlan?) {
            System.out.apply {
                println()
                println("----------------------------------")
                println("SAML Conformance Test Kit Starting")
                println("----------------------------------")
                println()
            }
        }

        override fun executionFinished(
            testIdentifier: TestIdentifier,
            testExecutionResult: TestExecutionResult
        ) {
            if (testIdentifier.isTest) {
                print(testIdentifier.displayName)
                if (Report.testHasExceptions()) {
                    print("  ${Ansi.ansi().fgRed().a(FAILED).reset()}")
                } else {
                    print("  ${Ansi.ansi().fgGreen().a(SUCCESSFUL).reset()}")
                }
                println()

                Report.printTestExceptions()
                Report.resetCurrentTestExceptions()
            }
        }
    }
}
