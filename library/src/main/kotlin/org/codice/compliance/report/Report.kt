/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.report

import org.codice.compliance.QUIET_MODE
import org.codice.compliance.RUN_DDF_PROFILE
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.Section
import org.codice.compliance.Section.GENERAL
import org.codice.compliance.Section.SCHEMA
import org.fusesource.jansi.Ansi
import java.io.File
import java.io.PrintWriter

@Suppress("MagicNumber")
object Report {

    internal const val REPORT_FILE = "report.txt"
    private const val NOT_TESTED_LIST =
            "https://github.com/codice/saml-conformance/blob/master/ctk/idp/NotTested.md"

    private val emptyExceptionMap: MutableMap<Section, MutableSet<SAMLComplianceException>?> =
            Section.values().map {
                it to null
            }.toMap().toMutableMap()

    private val exceptionMessages = mutableMapOf<Section, MutableSet<SAMLComplianceException>?>()
            .apply {
                putAll(emptyExceptionMap)
            }

    private var currentTestExceptionMessages = mutableSetOf<SAMLComplianceException>()

    private val reportQuietly by lazy {
        System.getProperty(QUIET_MODE)?.toBoolean() == true
    }

    private val runDDFProfile by lazy {
        System.getProperty(RUN_DDF_PROFILE)?.toBoolean() == true
    }

    private var hasExceptions = false

    /**
     * Adds an exception to the {@code exceptionMessages} for the given {@param section}
     *
     * @param section - the Section to add the exception to
     * @param exception - the SAML Compliance Exception to add
     */
    fun addExceptionMessage(
        exception: SAMLComplianceException,
        section: Section = exception.section
    ): Report {
        if (exceptionMessages[section] == null) {
            exceptionMessages[section] = mutableSetOf(exception)
        } else {
            exceptionMessages[section]?.add(exception)
        }

        currentTestExceptionMessages.add(exception)
        hasExceptions = true
        return this
    }

    /**
     * Returns the list of exceptions found for the given {@param section}
     *
     * @param section - the section of the exceptions
     * @return - A joint string containing all the exception for the given section
     */
    fun getExceptionMessages(section: Section): String {
        return exceptionMessages[section]?.joinToString() ?: ""
    }

    /**
     * Sets the exception message for the given {@param section}
     *
     * @param section - the section of the exceptions
     */
    internal fun setExceptionMessages(section: Section, set: MutableSet<SAMLComplianceException>?) {
        exceptionMessages[section] = set
    }

    /**
     * @return true if there are exceptions and false otherwise
     */
    fun hasExceptions(): Boolean {
        return hasExceptions
    }

    /**
     * @return true if the current test has exceptions and false otherwise
     */
    fun testHasExceptions(): Boolean {
        return currentTestExceptionMessages.isNotEmpty()
    }

    /**
     * Resets the list of the current test's exceptions
     */
    fun resetCurrentTestExceptions() {
        currentTestExceptionMessages = mutableSetOf()
    }

    /**
     * Resets the map of the current test's exceptions
     * This is used for testing purposes only
     */
    fun resetExceptionMap() {
        exceptionMessages.clear()
        exceptionMessages.putAll(emptyExceptionMap)
        hasExceptions = false
    }

    /**
     * Prints the test exceptions
     */
    fun printTestExceptions() {
        if (reportQuietly) {
            return
        }
        currentTestExceptionMessages.forEach {
            println(Ansi.ansi().fgMagenta().a(it.message).reset())
        }
    }

    /**
     * Writes the report to a file.
     *
     * Note: Section 3.3 is not fully tested. It's partially tested when it comes to Subject
     * Comparison and RequestedAuthnContext. The only time it should be displayed is when the
     * RequestedAuthnContext (3.3.2.2.1) is tested which is when the DDF profile is run.
     */
    @Suppress("ComplexMethod", "NestedBlockDepth")
    fun writeReport() {
        // GENERAL is never skipped
        if (exceptionMessages[GENERAL] == null) {
            GENERAL.start()
        }

        val file = File(REPORT_FILE)
        file.printWriter().use { writer ->
            Section.values().forEach { section ->
                when {
                    section.isDDFProfile() -> {
                        if (runDDFProfile) {
                            writer.print("\t".repeat(section.level))
                            writer.print(section.title)

                            if (section.level == 3) {
                                printExceptions(section, writer)
                            } else {
                                writer.println()
                            }
                        } else {
                            writer.print("\t".repeat(section.level))
                            writer.println(Ansi.ansi().fgBrightBlack().a(section.title).reset())
                        }
                    }
                    else -> {
                        writer.print("\t".repeat(section.level))
                        writer.print(section.title)

                        // the top level section will not have a status except GENERAL and SCHEMA
                        if (section.level == 2 || section == GENERAL || section == SCHEMA) {
                            printExceptions(section, writer)
                        } else {
                            writer.println()
                        }
                    }
                }
            }

            writer.println()
            writer.print("NOTE: A list of MUSTs that are hard to test can be found at: ")
            writer.print(Ansi.ansi().fgBrightBlue().a(NOT_TESTED_LIST).reset())
            writer.println()
        }

        println()
        print("A full report can be found at: ")
        print(Ansi.ansi().fgBrightBlue().a(file.absolutePath).reset())
        println()
        print("NOTE: A list of MUSTs that are hard to test can be found at: ")
        print(Ansi.ansi().fgBrightBlue().a(NOT_TESTED_LIST).reset())
        println()
    }

    private fun printExceptions(it: Section, writer: PrintWriter) {
        when {
            exceptionMessages[it] == null ->
                writer.print("  ${Ansi.ansi().fgYellow().a("SKIPPED").reset()}")
            exceptionMessages[it]?.isEmpty() == true ->
                writer.print("  ${Ansi.ansi().fgGreen().a("SUCCESSFUL").reset()}")
            else -> {
                writer.print("  ${Ansi.ansi().fgRed().a("FAILED").reset()}")
                writer.println()
                if (reportQuietly) {
                    return
                }
                exceptionMessages[it]?.forEach { exc ->
                    exc.let {
                        writer.println(Ansi.ansi().fgMagenta().a(it.message).reset())
                    }
                }
            }
        }
        writer.println()
    }
}
