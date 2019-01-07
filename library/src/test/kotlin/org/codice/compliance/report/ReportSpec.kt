/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.report

import io.kotlintest.matchers.boolean.shouldBeFalse
import io.kotlintest.matchers.boolean.shouldBeTrue
import io.kotlintest.matchers.file.shouldExist
import io.kotlintest.matchers.string.shouldBeBlank
import io.kotlintest.matchers.string.shouldContain
import io.kotlintest.matchers.string.shouldNotContain
import io.kotlintest.specs.StringSpec
import org.codice.compliance.SAMLBindings_3_1_2_1_a
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.SAMLCore_1_3_3_a
import org.codice.compliance.SAMLGeneral_a
import org.codice.compliance.Section.BINDINGS
import org.codice.compliance.Section.BINDINGS_3_1
import org.codice.compliance.Section.CORE_1_3
import org.codice.compliance.Section.GENERAL
import org.codice.compliance.report.Report.REPORT_FILE
import java.nio.file.Files
import java.nio.file.Paths

@Suppress("StringLiteralDuplication")
class ReportSpec : StringSpec() {
    init {

        "test adding and getting an exception after explicitly starting the section to the report" {
            Report.getExceptionMessages(BINDINGS_3_1).isNullOrBlank()

            BINDINGS_3_1.start()
            Report.getExceptionMessages(BINDINGS_3_1).shouldBeBlank()
            Report.hasExceptions().shouldBeFalse()

            Report.addExceptionMessage(
                    SAMLComplianceException.create(SAMLBindings_3_1_2_1_a, message = "message"))
            Report.getExceptionMessages(BINDINGS_3_1).shouldContain("message")
            Report.hasExceptions().shouldBeTrue()
            Report.testHasExceptions().shouldBeTrue()
        }

        "test adding an exception to a specified section" {
            Report.getExceptionMessages(BINDINGS).isNullOrBlank()
            Report.addExceptionMessage(
                    SAMLComplianceException.create(SAMLBindings_3_1_2_1_a, message = "message"),
                    BINDINGS)
            Report.getExceptionMessages(BINDINGS).shouldContain("message")
            Report.hasExceptions().shouldBeTrue()
            Report.testHasExceptions().shouldBeTrue()
        }

        "test adding and getting an exception to the report" {
            Report.addExceptionMessage(
                    SAMLComplianceException.create(SAMLGeneral_a, message = "message"))
            Report.getExceptionMessages(GENERAL).shouldContain("message")
            Report.hasExceptions().shouldBeTrue()
            Report.testHasExceptions().shouldBeTrue()
        }

        "test adding exception to the same section in the report" {
            Report.addExceptionMessage(
                    SAMLComplianceException.create(SAMLCore_1_3_3_a, message = "old message"))

            Report.addExceptionMessage(
                    SAMLComplianceException.create(SAMLCore_1_3_3_a, message = "new message"))

            Report.getExceptionMessages(CORE_1_3).shouldContain("old message")
            Report.getExceptionMessages(CORE_1_3).shouldNotContain("new message")
        }

        "test resenting the test exception list" {
            Report.addExceptionMessage(
                    SAMLComplianceException.create(SAMLBindings_3_1_2_1_a, message = "message"))
            Report.testHasExceptions().shouldBeTrue()
            Report.resetCurrentTestExceptions()
            Report.testHasExceptions().shouldBeFalse()
        }

        "test report creation" {
            Report.addExceptionMessage(
                    SAMLComplianceException.create(SAMLGeneral_a, message = "message"))
            Report.addExceptionMessage(
                    SAMLComplianceException.create(SAMLCore_1_3_3_a, message = "message"))
            Report.writeReport()
            val path = Paths.get(REPORT_FILE)
            path.shouldExist()

            //cleanup
            Files.delete(path)
        }
    }
}
