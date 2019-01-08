/*
Copyright (c) 2019 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.web

import io.kotlintest.Description
import io.kotlintest.TestResult
import io.kotlintest.extensions.TestListener
import org.codice.compliance.report.Report
import org.fusesource.jansi.Ansi
import org.junit.platform.engine.TestExecutionResult.Status.FAILED
import org.junit.platform.engine.TestExecutionResult.Status.SUCCESSFUL

object ResultListener : TestListener {

    /**
     * Used to report test status after each test.
     */
    override fun afterTest(description: Description, result: TestResult) {
        print(description.name)
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
