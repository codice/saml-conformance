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
@file:Suppress("ClassNaming")

package org.codice.compliance

import java.net.URI
import java.util.ResourceBundle

sealed class SAMLSpecRefMessage(docRefKey: String,
                                docUriKey: String) {
    private val docRef: String
    private val docUri: URI

    init {
        docRef = bundle.getString(docRefKey)
        docUri = URI(bundle.getString(docUriKey))
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

sealed class SAMLProfileRefMessage : SAMLSpecRefMessage("SAMLProfile.doc", "SAMLProfile.uri")
sealed class SAMLCoreRefMessage : SAMLSpecRefMessage("SAMLCore.doc", "SAMLCore.uri")
sealed class SAMLBindingRefMessage : SAMLSpecRefMessage("SAMLBinding.doc", "SAMLBinding.uri")
sealed class SAMLGeneralRefMessage : SAMLSpecRefMessage("SAMLGeneral.doc", "SAMLGeneral.uri")

//-----------------
// PROFILES
//-----------------
object SAMLProfiles_3_1_a : SAMLProfileRefMessage()
object SAMLProfiles_3_1_b : SAMLProfileRefMessage()
object SAMLProfiles_3_1_c : SAMLProfileRefMessage()

object SAMLProfiles_4_1_2_a : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_1_a : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_1_b : SAMLProfileRefMessage()

object SAMLProfiles_4_1_4_2_a : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_b : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_c : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_d : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_e : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_f : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_g : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_h : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_i : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_j : SAMLProfileRefMessage()

object SAMLProfiles_4_1_4_5_a : SAMLProfileRefMessage()

object SAMLProfiles_4_4_3_3_a : SAMLProfileRefMessage()

object SAMLProfiles_4_4_3_5_a : SAMLProfileRefMessage()

object SAMLProfiles_4_4_4_1_a : SAMLProfileRefMessage()
object SAMLProfiles_4_4_4_1_b : SAMLProfileRefMessage()
object SAMLProfiles_4_4_4_1_c : SAMLProfileRefMessage()

object SAMLProfiles_4_4_4_2_a : SAMLProfileRefMessage()
object SAMLProfiles_4_4_4_2_b : SAMLProfileRefMessage()

//-----------------
// CORE
//-----------------
object SAMLCore_Schema : SAMLCoreRefMessage()

object SAMLCore_1_3_1_a : SAMLCoreRefMessage()
object SAMLCore_1_3_2_a : SAMLCoreRefMessage()
object SAMLCore_1_3_3_a : SAMLCoreRefMessage()
object SAMLCore_1_3_4_a : SAMLCoreRefMessage()

object SAMLCore_2_2_3_a : SAMLCoreRefMessage()
object SAMLCore_2_2_3_b : SAMLCoreRefMessage()
object SAMLCore_2_2_4_a : SAMLCoreRefMessage()

object SAMLCore_2_3_3_a : SAMLCoreRefMessage()
object SAMLCore_2_3_3_b : SAMLCoreRefMessage()
object SAMLCore_2_3_3_c : SAMLCoreRefMessage()
object SAMLCore_2_3_4_a : SAMLCoreRefMessage()

object SAMLCore_2_4_1_2_a : SAMLCoreRefMessage()

object SAMLCore_2_5_1_a : SAMLCoreRefMessage()
object SAMLCore_2_5_1_b : SAMLCoreRefMessage()
object SAMLCore_2_5_1_c : SAMLCoreRefMessage()
object SAMLCore_2_5_1_2_a : SAMLCoreRefMessage()
object SAMLCore_2_5_1_5_a : SAMLCoreRefMessage()
object SAMLCore_2_5_1_6_a : SAMLCoreRefMessage()
object SAMLCore_2_5_1_6_b : SAMLCoreRefMessage()

object SAMLCore_2_7_2_a : SAMLCoreRefMessage()
object SAMLCore_2_7_3_a : SAMLCoreRefMessage()
object SAMLCore_2_7_3_2_a : SAMLCoreRefMessage()

object SAMLCore_2_7_4_a : SAMLCoreRefMessage()

object SAMLCore_3_2_1_a : SAMLCoreRefMessage()
object SAMLCore_3_2_1_b : SAMLCoreRefMessage()
object SAMLCore_3_2_1_c : SAMLCoreRefMessage()
object SAMLCore_3_2_1_d : SAMLCoreRefMessage()
object SAMLCore_3_2_1_e : SAMLCoreRefMessage()

object SAMLCore_3_2_2_a : SAMLCoreRefMessage()
object SAMLCore_3_2_2_b : SAMLCoreRefMessage()
object SAMLCore_3_2_2_c : SAMLCoreRefMessage()
object SAMLCore_3_2_2_d : SAMLCoreRefMessage()
object SAMLCore_3_2_2_e : SAMLCoreRefMessage()
object SAMLCore_3_2_2_2_a : SAMLCoreRefMessage()

object SAMLCore_3_3_4_a : SAMLCoreRefMessage()
object SAMLCore_3_3_4_b : SAMLCoreRefMessage()
object SAMLCore_3_3_4_c : SAMLCoreRefMessage()

object SAMLCore_3_4_a : SAMLCoreRefMessage()
object SAMLCore_3_4_1_a : SAMLCoreRefMessage()
object SAMLCore_3_4_1_1_a : SAMLCoreRefMessage()
object SAMLCore_3_4_1_1_b : SAMLCoreRefMessage()
object SAMLCore_3_4_1_4_a : SAMLCoreRefMessage()
object SAMLCore_3_4_1_4_b : SAMLCoreRefMessage()
object SAMLCore_3_4_1_4_c : SAMLCoreRefMessage()
object SAMLCore_3_4_1_4_d : SAMLCoreRefMessage()
object SAMLCore_3_4_1_4_e : SAMLCoreRefMessage()

object SAMLCore_3_7_1_a : SAMLCoreRefMessage()

object SAMLCore_3_7_3_2_a : SAMLCoreRefMessage()
object SAMLCore_3_7_3_2_b : SAMLCoreRefMessage()
object SAMLCore_3_7_3_2_c : SAMLCoreRefMessage()
object SAMLCore_3_7_3_2_d : SAMLCoreRefMessage()
object SAMLCore_3_7_3_2_e : SAMLCoreRefMessage()

object SAMLCore_4_1_2_a : SAMLCoreRefMessage()
object SAMLCore_4_1_3_2_a : SAMLCoreRefMessage()
object SAMLCore_4_1_3_2_b : SAMLCoreRefMessage()
object SAMLCore_4_1_3_3_a : SAMLCoreRefMessage()
object SAMLCore_4_2_a : SAMLCoreRefMessage()

object SAMLCore_5_4_2_a : SAMLCoreRefMessage()

object SAMLCore_6_1_a : SAMLCoreRefMessage()
object SAMLCore_6_1_b : SAMLCoreRefMessage()

object SAMLCore_8_1_2_a : SAMLCoreRefMessage()

object SAMLCore_8_2_2_a : SAMLCoreRefMessage()
object SAMLCore_8_2_3_a : SAMLCoreRefMessage()

object SAMLCore_8_3_2_a : SAMLCoreRefMessage()
object SAMLCore_8_3_6_a : SAMLCoreRefMessage()
object SAMLCore_8_3_6_b : SAMLCoreRefMessage()

object SAMLCore_8_3_7_a : SAMLCoreRefMessage()
object SAMLCore_8_3_7_b : SAMLCoreRefMessage()
object SAMLCore_8_3_7_c : SAMLCoreRefMessage()
object SAMLCore_8_3_7_d : SAMLCoreRefMessage()

object SAMLCore_8_3_8_a : SAMLCoreRefMessage()

//-----------------
// BINDINGS
//-----------------
object SAMLBindings_3_1_2_1_a : SAMLBindingRefMessage()

object SAMLBindings_3_4_3_a : SAMLBindingRefMessage()
object SAMLBindings_3_4_3_b : SAMLBindingRefMessage()

object SAMLBindings_3_4_4_a : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_b : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_a : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_b : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_c : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_d : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_e : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_f : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_g : SAMLBindingRefMessage()

object SAMLBindings_3_4_6_a : SAMLBindingRefMessage()
object SAMLBindings_3_5_3_a : SAMLBindingRefMessage()
object SAMLBindings_3_5_3_b : SAMLBindingRefMessage()
object SAMLBindings_3_5_4_a : SAMLBindingRefMessage()
object SAMLBindings_3_5_4_b : SAMLBindingRefMessage()
object SAMLBindings_3_5_4_c : SAMLBindingRefMessage()
object SAMLBindings_3_5_4_d : SAMLBindingRefMessage()
object SAMLBindings_3_5_5_2_a : SAMLBindingRefMessage()

//------------------
// GENERAL
//------------------
object SAMLGeneral_a : SAMLGeneralRefMessage()
object SAMLGeneral_b : SAMLGeneralRefMessage()
object SAMLGeneral_c : SAMLGeneralRefMessage()
object SAMLGeneral_d : SAMLGeneralRefMessage()
object SAMLGeneral_e : SAMLGeneralRefMessage()
