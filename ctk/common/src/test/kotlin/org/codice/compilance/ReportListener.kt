/*
Copyright (c) 2019 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compilance

import io.kotlintest.Description
import io.kotlintest.TestResult
import io.kotlintest.extensions.TestListener
import org.codice.compliance.report.Report

/**
 * Listener used to reset the Report map for testing purposes before each test
 */
object ReportListener : TestListener {

    override fun afterTest(description: Description, result: TestResult) {
        Report.resetExceptionMap()
    }
}
