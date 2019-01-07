/*
Copyright (c) 2019 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance

import org.codice.compliance.report.Report

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
        if (Report.getExceptionMessages(this).isBlank()) {
            Report.setExceptionMessages(this, mutableSetOf())
        }
    }

    /**
     * Marks a {@code Section} as skipped by setting it to null in the error map
     */
    fun skip() {
        Report.setExceptionMessages(this, null)
    }
}
