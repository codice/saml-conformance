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

import java.util.ResourceBundle

sealed class SAMLSpecRefMessage {
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

//-----------------
// PROFILES
//-----------------
object SAMLProfiles_3_1_a : SAMLSpecRefMessage()
object SAMLProfiles_3_1_b : SAMLSpecRefMessage()
object SAMLProfiles_3_1_c : SAMLSpecRefMessage()

object SAMLProfiles_4_1_4_2_a : SAMLSpecRefMessage()
object SAMLProfiles_4_1_4_2_b : SAMLSpecRefMessage()
object SAMLProfiles_4_1_4_2_c : SAMLSpecRefMessage()
object SAMLProfiles_4_1_4_2_d : SAMLSpecRefMessage()
// object SAMLProfiles_4_1_4_2e : SAMLSpecRefMessage()
object SAMLProfiles_4_1_4_2_f : SAMLSpecRefMessage()

object SAMLProfiles_4_1_4_2_g : SAMLSpecRefMessage()
object SAMLProfiles_4_1_4_2_h : SAMLSpecRefMessage()
object SAMLProfiles_4_1_4_2_i : SAMLSpecRefMessage()
object SAMLProfiles_4_1_4_2_j : SAMLSpecRefMessage()
object SAMLProfiles_4_1_4_2_k : SAMLSpecRefMessage()
object SAMLProfiles_4_1_4_5 : SAMLSpecRefMessage()

//-----------------
// CORE
//-----------------
object SAMLCore_1_3_1_a : SAMLSpecRefMessage()

object SAMLCore_1_3_2_a : SAMLSpecRefMessage()
object SAMLCore_1_3_3 : SAMLSpecRefMessage()
object SAMLCore_1_3_4 : SAMLSpecRefMessage()

object SAMLCore_2_2_3_a : SAMLSpecRefMessage()
object SAMLCore_2_2_3_b : SAMLSpecRefMessage()

object SAMLCore_2_2_4_a : SAMLSpecRefMessage()
// todo object SAMLCore_2_2_4_b : SAMLSpecRefMessage()
// todo object SAMLCore_2_2_4_c : SAMLSpecRefMessage()

object SAMLCore_2_3_3_a : SAMLSpecRefMessage()
object SAMLCore_2_3_3_b : SAMLSpecRefMessage()
object SAMLCore_2_3_3_c : SAMLSpecRefMessage()
object SAMLCore_2_3_4_a : SAMLSpecRefMessage()
// todo object SAMLCore_2_3_4_b : SAMLSpecRefMessage()

// todo object SAMLCore_2_4_1_2_b : SAMLSpecRefMessage()

object SAMLCore_2_4_1_2_b : SAMLSpecRefMessage()
object SAMLCore_2_4_1_3 : SAMLSpecRefMessage()

object SAMLCore_2_5_1_a : SAMLSpecRefMessage()
object SAMLCore_2_5_1_b : SAMLSpecRefMessage()
object SAMLCore_2_5_1_c : SAMLSpecRefMessage()
object SAMLCore_2_5_1_2 : SAMLSpecRefMessage()
object SAMLCore_2_5_1_5 : SAMLSpecRefMessage()
object SAMLCore_2_5_1_6_a : SAMLSpecRefMessage()
object SAMLCore_2_5_1_6_b : SAMLSpecRefMessage()

object SAMLCore_2_7_2 : SAMLSpecRefMessage()
object SAMLCore_2_7_3 : SAMLSpecRefMessage()
object SAMLCore_2_7_3_1_1 : SAMLSpecRefMessage()
object SAMLCore_2_7_3_2_a : SAMLSpecRefMessage()
// todo object SAMLCore_2_7_3_2_b : SAMLSpecRefMessage()

object SAMLCore_2_7_4 : SAMLSpecRefMessage()

object SAMLCore_3_2_1_a : SAMLSpecRefMessage()
object SAMLCore_3_2_1_b : SAMLSpecRefMessage()
object SAMLCore_3_2_1_c : SAMLSpecRefMessage()
object SAMLCore_3_2_2_a : SAMLSpecRefMessage()
object SAMLCore_3_2_2_b : SAMLSpecRefMessage()
object SAMLCore_3_2_2_c : SAMLSpecRefMessage()
object SAMLCore_3_2_2_d : SAMLSpecRefMessage()
object SAMLCore_3_2_2_e : SAMLSpecRefMessage()
object SAMLCore_3_2_2_2 : SAMLSpecRefMessage()

object SAMLCore_3_3_2_2_a : SAMLSpecRefMessage()
object SAMLCore_3_3_2_2_b : SAMLSpecRefMessage()
object SAMLCore_3_3_2_3 : SAMLSpecRefMessage()

object SAMLCore_3_4 : SAMLSpecRefMessage()
// todo object SAMLCore_3_4_1_1_a : SAMLSpecRefMessage()

object SAMLCore_3_7_1 : SAMLSpecRefMessage()

object SAMLCore_5_4_1 : SAMLSpecRefMessage()
object SAMLCore_5_4_2_a : SAMLSpecRefMessage()
object SAMLCore_5_4_2_b : SAMLSpecRefMessage()
object SAMLCore_5_4_2_b1 : SAMLSpecRefMessage()

// todo object SAMLCore_6_1_a : SAMLSpecRefMessage()
object SAMLCore_6_1_b : SAMLSpecRefMessage()

//-----------------
// BINDINGS
//-----------------
// todo object SAMLBindings_3_1_1_b : SAMLSpecRefMessage()
object SAMLBindings_3_1_2_1 : SAMLSpecRefMessage()

object SAMLBindings_3_4_3_a : SAMLSpecRefMessage()
object SAMLBindings_3_4_3_b1 : SAMLSpecRefMessage()
object SAMLBindings_3_4_4_a : SAMLSpecRefMessage()
object SAMLBindings_3_4_4_1 : SAMLSpecRefMessage()
object SAMLBindings_3_4_4_1_a : SAMLSpecRefMessage()
object SAMLBindings_3_4_4_1_a1 : SAMLSpecRefMessage()
object SAMLBindings_3_4_4_1_a2 : SAMLSpecRefMessage()
// todo object SAMLBindings_3_4_4_1_b : SAMLSpecRefMessage()
object SAMLBindings_3_4_4_1_b1 : SAMLSpecRefMessage()

object SAMLBindings_3_4_4_1_b2 : SAMLSpecRefMessage()
object SAMLBindings_3_4_4_1_c1 : SAMLSpecRefMessage()
object SAMLBindings_3_4_4_1_c2 : SAMLSpecRefMessage()
object SAMLBindings_3_4_4_1_d1 : SAMLSpecRefMessage()
object SAMLBindings_3_4_4_1_d2 : SAMLSpecRefMessage()
object SAMLBindings_3_4_4_1_e : SAMLSpecRefMessage()
object SAMLBindings_3_4_4_1_f1 : SAMLSpecRefMessage()
object SAMLBindings_3_4_4_1_f2 : SAMLSpecRefMessage()
// todo object SAMLBindings_3_4_4_1_g : SAMLSpecRefMessage()
object SAMLBindings_3_4_5_2_a1 : SAMLSpecRefMessage()
// todo object SAMLBindings_3_4_5_2_a2 : SAMLSpecRefMessage()

object SAMLBindings_3_4_6_a : SAMLSpecRefMessage()
object SAMLBindings_3_5_3_a : SAMLSpecRefMessage()
object SAMLBindings_3_5_3_b : SAMLSpecRefMessage()
object SAMLBindings_3_5_4_a : SAMLSpecRefMessage()
object SAMLBindings_3_5_4_a1 : SAMLSpecRefMessage()
object SAMLBindings_3_5_4_a2 : SAMLSpecRefMessage()
object SAMLBindings_3_5_4_b : SAMLSpecRefMessage()
object SAMLBindings_3_5_4_b1 : SAMLSpecRefMessage()
object SAMLBindings_3_5_4_c : SAMLSpecRefMessage()
object SAMLBindings_3_5_4_d : SAMLSpecRefMessage()
object SAMLBindings_3_5_4_d1 : SAMLSpecRefMessage()
object SAMLBindings_3_5_4_d2 : SAMLSpecRefMessage()
object SAMLBindings_3_5_5_2_a : SAMLSpecRefMessage()
object SAMLBindings_3_5_6_a : SAMLSpecRefMessage()

//-----------------
// XML Datatype Schema
//-----------------

object XMLDatatypesSchema_3_2_7 : SAMLSpecRefMessage()
object XMLDatatypesSchema_3_2_7_1_a : SAMLSpecRefMessage()
object XMLDatatypesSchema_3_2_7_1_b : SAMLSpecRefMessage()
object XMLDatatypesSchema_3_2_7_1_c : SAMLSpecRefMessage()

//-----------------
// XML Signature Syntax and Processing
//-----------------

object XMLSignature_4_5 : SAMLSpecRefMessage()
