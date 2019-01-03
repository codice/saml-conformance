/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.report

import org.codice.compliance.QUIET_MODE
import org.codice.compliance.SAMLComplianceException
import org.codice.compliance.report.Report.Section.GENERAL
import org.codice.compliance.report.Report.Section.SCHEMA
import org.fusesource.jansi.Ansi
import java.io.File
import java.io.PrintWriter

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
        QUIET_MODE.toBoolean()
    }

    private var hasExceptions = false

    /**
     * Adds an exception to the {@code exceptionMessages} for the given {@param exception}'s section
     *
     * @param exception - the SAML Compliance Exception to add
     */
    fun addExceptionMessage(exception: SAMLComplianceException): Report {
        val section = exception.section
        if (!section.isStarted()) {
            exceptionMessages[section] = mutableSetOf(exception)
        } else {
            exceptionMessages[section]?.add(exception)
        }

        currentTestExceptionMessages.add(exception)
        hasExceptions = true
        return this
    }

    /**
     * Adds an exception to the {@code exceptionMessages} for the given {@param section}
     *
     * @param section - the Section to add the exception to
     * @param exception - the SAML Compliance Exception to add
     */
    fun addExceptionMessage(section: Section, exception: SAMLComplianceException): Report {
        if (!section.isStarted()) {
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
     */
    fun writeReport() {
        val file = File(REPORT_FILE)
        file.printWriter().use { writer ->
            Section.values().forEach { section ->
                writer.print("\t".repeat(section.level))
                writer.print(section.title)

                // the top level section will not have a status except GENERAL and SCHEMA
                if (section.level == 2 || section == GENERAL || section == SCHEMA) {
                    printExceptions(section, writer)
                } else {
                    writer.println()
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

    enum class Section(val title: String, val level: Int = 1) {
        GENERAL("GENERAL", 0),
        SCHEMA("SCHEMA", 0),
        CORE("CORE", 0),

        CORE_1("1 Introduction"),
        CORE_1_3("1.3 Common Data Types", 2),

        CORE_2("2 SAML Assertions"),
        CORE_2_2("2.2 Name Identifiers", 2),
        CORE_2_3("2.3 Assertions", 2),
        CORE_2_4("2.4 Subjects", 2),
        CORE_2_5("2.5 Conditions", 2),
        CORE_2_7("2.7 Statements", 2),

        CORE_3("3 SAML Protocols"),
        CORE_3_2("3.2 Requests and Responses", 2),
        CORE_3_3("3.3 Assertion Query and Request Protocol", 2),
        CORE_3_4("3.4 Authentication Request Protocol.", 2),
        CORE_3_7("3.7 Single Logout Protocol.", 2),

        CORE_4("4 SAML Versioning"),
        CORE_4_1("4.1 SAML Specification Set Version", 2),
        CORE_4_2("4.2 SAML Namespace Version", 2),

        CORE_5("5 SAML and XML Signature Syntax and Processing"),
        CORE_5_4("5.4 XML Signature Profile", 2),

        CORE_6("6 SAML and XML Encryption Syntax and Processing"),
        CORE_6_1("6.1 General Considerations", 2),

        CORE_8("8 SAML-Defined Identifiers"),
        CORE_8_2("8.2 Attribute Name Format Identifiers", 2),
        CORE_8_3("8.3 Name Identifier Format Identifiers", 2),

        BINDINGS("BINDINGS", 0),
        BINDINGS_3("3 Protocol Bindings"),
        BINDINGS_3_1("3.1 General Considerations", 2),
        BINDINGS_3_4("3.4 HTTP Redirect Binding", 2),
        BINDINGS_3_5("3.5 HTTP POST Binding", 2),

        PROFILES("PROFILES", 0),
        PROFILES_3("3 Confirmation Method Identifiers"),
        PROFILES_3_1("3.1 Holder of Key", 2),

        PROFILES_4("4 SSO Profiles of SAML"),
        PROFILES_4_1("4.1 Web Browser SSO Profile", 2),
        PROFILES_4_4("4.4 Single Logout Profile", 2);

        /**
         * Adds an empty set to the exception map of the given {@code Section}.
         * This allows the Report to know when a section is skipped.
         */
        fun start() {
            if (!this.isStarted()) {
                exceptionMessages[this] = mutableSetOf()
            }
        }

        /**
         * @return true if the section is started (has a set in the exception map)
         * and false otherwise
         */
        fun isStarted(): Boolean {
            return exceptionMessages[this] != null
        }

        /**
         * Marks a {@code Section} as skipped by setting it to null in the error map
         */
        fun skip() {
            exceptionMessages[this] = null
        }
    }
}
