/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
@file:Suppress("ClassNaming")

package org.codice.compliance

import org.codice.compliance.report.Report.Section
import org.codice.compliance.report.Report.Section.BINDINGS_3_1
import org.codice.compliance.report.Report.Section.BINDINGS_3_4
import org.codice.compliance.report.Report.Section.BINDINGS_3_5
import org.codice.compliance.report.Report.Section.CORE_1_3
import org.codice.compliance.report.Report.Section.CORE_2_2
import org.codice.compliance.report.Report.Section.CORE_2_3
import org.codice.compliance.report.Report.Section.CORE_2_4
import org.codice.compliance.report.Report.Section.CORE_2_5
import org.codice.compliance.report.Report.Section.CORE_2_7
import org.codice.compliance.report.Report.Section.CORE_3_2
import org.codice.compliance.report.Report.Section.CORE_3_3
import org.codice.compliance.report.Report.Section.CORE_3_4
import org.codice.compliance.report.Report.Section.CORE_3_7
import org.codice.compliance.report.Report.Section.CORE_4_1
import org.codice.compliance.report.Report.Section.CORE_4_2
import org.codice.compliance.report.Report.Section.CORE_5_4
import org.codice.compliance.report.Report.Section.CORE_6_1
import org.codice.compliance.report.Report.Section.CORE_8_2
import org.codice.compliance.report.Report.Section.CORE_8_3
import org.codice.compliance.report.Report.Section.GENERAL
import org.codice.compliance.report.Report.Section.PROFILES_3_1
import org.codice.compliance.report.Report.Section.PROFILES_4_1
import org.codice.compliance.report.Report.Section.PROFILES_4_4
import org.codice.compliance.report.Report.Section.SCHEMA
import java.net.URI
import java.util.ResourceBundle

sealed class SAMLSpecRefMessage(
    sec: Section,
    docRefKey: String,
    docUriKey: String
) {
    private val docRef: String
    private val docUri: URI
    val section: Section

    init {
        docRef = bundle.getString(docRefKey)
        docUri = URI(bundle.getString(docUriKey))
        section = sec
    }

    companion object {
        private val bundle = ResourceBundle.getBundle("SAMLSpecRefMessage")
    }

    val name: String by lazy {
        javaClass.simpleName
    }

    val message: String by lazy {
        bundle.getString(name)
    }
}

sealed class SAMLProfileRefMessage(sec: Section) :
        SAMLSpecRefMessage(sec, "SAMLProfile.doc", "SAMLProfile.uri")

sealed class SAMLCoreRefMessage(sec: Section) :
        SAMLSpecRefMessage(sec, "SAMLCore.doc", "SAMLCore.uri")

sealed class SAMLBindingRefMessage(sec: Section) :
        SAMLSpecRefMessage(sec, "SAMLBinding.doc", "SAMLBinding.uri")

sealed class SAMLGeneralRefMessage(sec: Section) :
        SAMLSpecRefMessage(sec, "SAMLGeneral.doc", "SAMLGeneral.uri")

//-----------------
// PROFILES
//-----------------
object SAMLProfiles_3_1_a : SAMLProfileRefMessage(PROFILES_3_1)
object SAMLProfiles_3_1_b : SAMLProfileRefMessage(PROFILES_3_1)
object SAMLProfiles_3_1_c : SAMLProfileRefMessage(PROFILES_3_1)

object SAMLProfiles_4_1_2_a : SAMLProfileRefMessage(PROFILES_4_1)
object SAMLProfiles_4_1_4_1_a : SAMLProfileRefMessage(PROFILES_4_1)
object SAMLProfiles_4_1_4_1_b : SAMLProfileRefMessage(PROFILES_4_1)
object SAMLProfiles_4_1_4_2_a : SAMLProfileRefMessage(PROFILES_4_1)
object SAMLProfiles_4_1_4_2_b : SAMLProfileRefMessage(PROFILES_4_1)
object SAMLProfiles_4_1_4_2_c : SAMLProfileRefMessage(PROFILES_4_1)
object SAMLProfiles_4_1_4_2_d : SAMLProfileRefMessage(PROFILES_4_1)
object SAMLProfiles_4_1_4_2_e : SAMLProfileRefMessage(PROFILES_4_1)
object SAMLProfiles_4_1_4_2_f : SAMLProfileRefMessage(PROFILES_4_1)
object SAMLProfiles_4_1_4_2_g : SAMLProfileRefMessage(PROFILES_4_1)
object SAMLProfiles_4_1_4_2_h : SAMLProfileRefMessage(PROFILES_4_1)
object SAMLProfiles_4_1_4_2_i : SAMLProfileRefMessage(PROFILES_4_1)
object SAMLProfiles_4_1_4_2_j : SAMLProfileRefMessage(PROFILES_4_1)
object SAMLProfiles_4_1_4_5_a : SAMLProfileRefMessage(PROFILES_4_1)

object SAMLProfiles_4_4_3_3_a : SAMLProfileRefMessage(PROFILES_4_4)
object SAMLProfiles_4_4_3_5_a : SAMLProfileRefMessage(PROFILES_4_4)
object SAMLProfiles_4_4_4_1_a : SAMLProfileRefMessage(PROFILES_4_4)
object SAMLProfiles_4_4_4_1_b : SAMLProfileRefMessage(PROFILES_4_4)
object SAMLProfiles_4_4_4_1_c : SAMLProfileRefMessage(PROFILES_4_4)
object SAMLProfiles_4_4_4_2_a : SAMLProfileRefMessage(PROFILES_4_4)
object SAMLProfiles_4_4_4_2_b : SAMLProfileRefMessage(PROFILES_4_4)

//-----------------
// CORE
//-----------------
object SAMLCore_Schema : SAMLCoreRefMessage(SCHEMA)

object SAMLCore_1_3_1_a : SAMLCoreRefMessage(CORE_1_3)
object SAMLCore_1_3_2_a : SAMLCoreRefMessage(CORE_1_3)
object SAMLCore_1_3_3_a : SAMLCoreRefMessage(CORE_1_3)
object SAMLCore_1_3_4_a : SAMLCoreRefMessage(CORE_1_3)

object SAMLCore_2_2_3_a : SAMLCoreRefMessage(CORE_2_2)
object SAMLCore_2_2_3_b : SAMLCoreRefMessage(CORE_2_2)
object SAMLCore_2_2_4_a : SAMLCoreRefMessage(CORE_2_2)

object SAMLCore_2_3_3_a : SAMLCoreRefMessage(CORE_2_3)
object SAMLCore_2_3_3_b : SAMLCoreRefMessage(CORE_2_3)
object SAMLCore_2_3_3_c : SAMLCoreRefMessage(CORE_2_3)
object SAMLCore_2_3_4_a : SAMLCoreRefMessage(CORE_2_3)

object SAMLCore_2_4_1_2_a : SAMLCoreRefMessage(CORE_2_4)

object SAMLCore_2_5_1_a : SAMLCoreRefMessage(CORE_2_5)
object SAMLCore_2_5_1_b : SAMLCoreRefMessage(CORE_2_5)
object SAMLCore_2_5_1_c : SAMLCoreRefMessage(CORE_2_5)
object SAMLCore_2_5_1_2_a : SAMLCoreRefMessage(CORE_2_5)
object SAMLCore_2_5_1_5_a : SAMLCoreRefMessage(CORE_2_5)
object SAMLCore_2_5_1_6_a : SAMLCoreRefMessage(CORE_2_5)
object SAMLCore_2_5_1_6_b : SAMLCoreRefMessage(CORE_2_5)

object SAMLCore_2_7_2_a : SAMLCoreRefMessage(CORE_2_7)
object SAMLCore_2_7_3_a : SAMLCoreRefMessage(CORE_2_7)
object SAMLCore_2_7_3_2_a : SAMLCoreRefMessage(CORE_2_7)
object SAMLCore_2_7_4_a : SAMLCoreRefMessage(CORE_2_7)

object SAMLCore_3_2_1_a : SAMLCoreRefMessage(CORE_3_2)
object SAMLCore_3_2_1_b : SAMLCoreRefMessage(CORE_3_2)
object SAMLCore_3_2_1_c : SAMLCoreRefMessage(CORE_3_2)
object SAMLCore_3_2_1_d : SAMLCoreRefMessage(CORE_3_2)
object SAMLCore_3_2_1_e : SAMLCoreRefMessage(CORE_3_2)
object SAMLCore_3_2_2_a : SAMLCoreRefMessage(CORE_3_2)
object SAMLCore_3_2_2_b : SAMLCoreRefMessage(CORE_3_2)
object SAMLCore_3_2_2_c : SAMLCoreRefMessage(CORE_3_2)
object SAMLCore_3_2_2_d : SAMLCoreRefMessage(CORE_3_2)
object SAMLCore_3_2_2_e : SAMLCoreRefMessage(CORE_3_2)
object SAMLCore_3_2_2_2_a : SAMLCoreRefMessage(CORE_3_2)

object SAMLCore_3_3_2_2_1_a : SAMLCoreRefMessage(CORE_3_3)
object SAMLCore_3_3_4_a : SAMLCoreRefMessage(CORE_3_3)
object SAMLCore_3_3_4_b : SAMLCoreRefMessage(CORE_3_3)
object SAMLCore_3_3_4_c : SAMLCoreRefMessage(CORE_3_3)

object SAMLCore_3_4_a : SAMLCoreRefMessage(CORE_3_4)
object SAMLCore_3_4_1_a : SAMLCoreRefMessage(CORE_3_4)
object SAMLCore_3_4_1_1_a : SAMLCoreRefMessage(CORE_3_4)
object SAMLCore_3_4_1_1_b : SAMLCoreRefMessage(CORE_3_4)
object SAMLCore_3_4_1_4_a : SAMLCoreRefMessage(CORE_3_4)
object SAMLCore_3_4_1_4_b : SAMLCoreRefMessage(CORE_3_4)
object SAMLCore_3_4_1_4_c : SAMLCoreRefMessage(CORE_3_4)
object SAMLCore_3_4_1_4_d : SAMLCoreRefMessage(CORE_3_4)
object SAMLCore_3_4_1_4_e : SAMLCoreRefMessage(CORE_3_4)

object SAMLCore_3_7_1_a : SAMLCoreRefMessage(CORE_3_7)
object SAMLCore_3_7_3_2_a : SAMLCoreRefMessage(CORE_3_7)
object SAMLCore_3_7_3_2_b : SAMLCoreRefMessage(CORE_3_7)
object SAMLCore_3_7_3_2_c : SAMLCoreRefMessage(CORE_3_7)
object SAMLCore_3_7_3_2_d : SAMLCoreRefMessage(CORE_3_7)
object SAMLCore_3_7_3_2_e : SAMLCoreRefMessage(CORE_3_7)

object SAMLCore_4_1_2_a : SAMLCoreRefMessage(CORE_4_1)
object SAMLCore_4_1_3_2_a : SAMLCoreRefMessage(CORE_4_1)
object SAMLCore_4_1_3_2_b : SAMLCoreRefMessage(CORE_4_1)
object SAMLCore_4_1_3_3_a : SAMLCoreRefMessage(CORE_4_1)

object SAMLCore_4_2_a : SAMLCoreRefMessage(CORE_4_2)

object SAMLCore_5_4_2_a : SAMLCoreRefMessage(CORE_5_4)

object SAMLCore_6_1_a : SAMLCoreRefMessage(CORE_6_1)
object SAMLCore_6_1_b : SAMLCoreRefMessage(CORE_6_1)

object SAMLCore_8_2_2_a : SAMLCoreRefMessage(CORE_8_2)
object SAMLCore_8_2_3_a : SAMLCoreRefMessage(CORE_8_2)

object SAMLCore_8_3_2_a : SAMLCoreRefMessage(CORE_8_3)
object SAMLCore_8_3_6_a : SAMLCoreRefMessage(CORE_8_3)
object SAMLCore_8_3_6_b : SAMLCoreRefMessage(CORE_8_3)
object SAMLCore_8_3_7_a : SAMLCoreRefMessage(CORE_8_3)
object SAMLCore_8_3_7_b : SAMLCoreRefMessage(CORE_8_3)
object SAMLCore_8_3_7_c : SAMLCoreRefMessage(CORE_8_3)
object SAMLCore_8_3_7_d : SAMLCoreRefMessage(CORE_8_3)
object SAMLCore_8_3_8_a : SAMLCoreRefMessage(CORE_8_3)

//-----------------
// BINDINGS
//-----------------
object SAMLBindings_3_1_2_1_a : SAMLBindingRefMessage(BINDINGS_3_1)

object SAMLBindings_3_4_3_a : SAMLBindingRefMessage(BINDINGS_3_4)
object SAMLBindings_3_4_3_b : SAMLBindingRefMessage(BINDINGS_3_4)
object SAMLBindings_3_4_4_a : SAMLBindingRefMessage(BINDINGS_3_4)
object SAMLBindings_3_4_4_b : SAMLBindingRefMessage(BINDINGS_3_4)
object SAMLBindings_3_4_4_1_a : SAMLBindingRefMessage(BINDINGS_3_4)
object SAMLBindings_3_4_4_1_b : SAMLBindingRefMessage(BINDINGS_3_4)
object SAMLBindings_3_4_4_1_c : SAMLBindingRefMessage(BINDINGS_3_4)
object SAMLBindings_3_4_4_1_d : SAMLBindingRefMessage(BINDINGS_3_4)
object SAMLBindings_3_4_4_1_e : SAMLBindingRefMessage(BINDINGS_3_4)
object SAMLBindings_3_4_4_1_f : SAMLBindingRefMessage(BINDINGS_3_4)
object SAMLBindings_3_4_4_1_g : SAMLBindingRefMessage(BINDINGS_3_4)
object SAMLBindings_3_4_6_a : SAMLBindingRefMessage(BINDINGS_3_4)

object SAMLBindings_3_5_3_a : SAMLBindingRefMessage(BINDINGS_3_5)
object SAMLBindings_3_5_3_b : SAMLBindingRefMessage(BINDINGS_3_5)
object SAMLBindings_3_5_4_a : SAMLBindingRefMessage(BINDINGS_3_5)
object SAMLBindings_3_5_4_b : SAMLBindingRefMessage(BINDINGS_3_5)
object SAMLBindings_3_5_4_c : SAMLBindingRefMessage(BINDINGS_3_5)
object SAMLBindings_3_5_4_d : SAMLBindingRefMessage(BINDINGS_3_5)
object SAMLBindings_3_5_5_2_a : SAMLBindingRefMessage(BINDINGS_3_5)

//------------------
// GENERAL
//------------------
object SAMLGeneral_a : SAMLGeneralRefMessage(GENERAL)
object SAMLGeneral_b : SAMLGeneralRefMessage(GENERAL)
object SAMLGeneral_c : SAMLGeneralRefMessage(GENERAL)
object SAMLGeneral_d : SAMLGeneralRefMessage(GENERAL)
object SAMLGeneral_e : SAMLGeneralRefMessage(GENERAL)
