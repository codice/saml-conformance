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
sealed class XmlDatatypeRefMessage : SAMLSpecRefMessage("XMLDatatype.doc", "XMLDatatype.uri")
sealed class XmlSigRefMessage : SAMLSpecRefMessage("XMLSig.doc", "XMLSig.uri")

//-----------------
// PROFILES
//-----------------
object SAMLProfiles_3_1_a : SAMLProfileRefMessage()

object SAMLProfiles_3_1_b : SAMLProfileRefMessage()
object SAMLProfiles_3_1_c : SAMLProfileRefMessage()

object SAMLProfiles_4_1_2 : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_1_a : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_1_b : SAMLProfileRefMessage()

object SAMLProfiles_4_1_4_2_a : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_b : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_c : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_d : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_f : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_g : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_h : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_i : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_j : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_k : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_2_l : SAMLProfileRefMessage()
object SAMLProfiles_4_1_4_5 : SAMLProfileRefMessage()

//-----------------
// CORE
//-----------------
object SAMLCore_Schema : SAMLCoreRefMessage()

object SAMLCore_1_3_1_a : SAMLCoreRefMessage()

object SAMLCore_1_3_2_a : SAMLCoreRefMessage()
object SAMLCore_1_3_3 : SAMLCoreRefMessage()
object SAMLCore_1_3_4 : SAMLCoreRefMessage()

object SAMLCore_2_2_3_a : SAMLCoreRefMessage()
object SAMLCore_2_2_3_b : SAMLCoreRefMessage()
object SAMLCore_2_2_4_a : SAMLCoreRefMessage()

object SAMLCore_2_3_3_a : SAMLCoreRefMessage()
object SAMLCore_2_3_3_b : SAMLCoreRefMessage()
object SAMLCore_2_3_3_c : SAMLCoreRefMessage()
object SAMLCore_2_3_4_a : SAMLCoreRefMessage()

object SAMLCore_2_4_1_2_b : SAMLCoreRefMessage()
object SAMLCore_2_4_1_2_c : SAMLCoreRefMessage()

object SAMLCore_2_4_1_3 : SAMLCoreRefMessage()

object SAMLCore_2_5_1_a : SAMLCoreRefMessage()
object SAMLCore_2_5_1_b : SAMLCoreRefMessage()
object SAMLCore_2_5_1_c : SAMLCoreRefMessage()
object SAMLCore_2_5_1_2 : SAMLCoreRefMessage()
object SAMLCore_2_5_1_5 : SAMLCoreRefMessage()
object SAMLCore_2_5_1_6_a : SAMLCoreRefMessage()
object SAMLCore_2_5_1_6_b : SAMLCoreRefMessage()

object SAMLCore_2_7_2 : SAMLCoreRefMessage()
object SAMLCore_2_7_3 : SAMLCoreRefMessage()
object SAMLCore_2_7_3_1 : SAMLCoreRefMessage()
object SAMLCore_2_7_3_1_1 : SAMLCoreRefMessage()
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
object SAMLCore_3_2_2_2 : SAMLCoreRefMessage()

object SAMLCore_3_3_2_2_a : SAMLCoreRefMessage()
object SAMLCore_3_3_2_2_b : SAMLCoreRefMessage()
object SAMLCore_3_3_2_3 : SAMLCoreRefMessage()

object SAMLCore_3_4 : SAMLCoreRefMessage()

object SAMLCore_3_7_1 : SAMLCoreRefMessage()

object SAMLCore_5_4_1 : SAMLCoreRefMessage()
object SAMLCore_5_4_2_a : SAMLCoreRefMessage()
object SAMLCore_5_4_2_b : SAMLCoreRefMessage()
object SAMLCore_5_4_2_b1 : SAMLCoreRefMessage()

object SAMLCore_6_1_b : SAMLCoreRefMessage()

object SAMLCore_8_1_2 : SAMLCoreRefMessage()

object SAMLCore_8_2_2 : SAMLCoreRefMessage()
object SAMLCore_8_2_3 : SAMLCoreRefMessage()

//-----------------
// BINDINGS
//-----------------
object SAMLBindings_3_1_2_1 : SAMLBindingRefMessage()

object SAMLBindings_3_4_3_a : SAMLBindingRefMessage()
object SAMLBindings_3_4_3_a1 : SAMLBindingRefMessage()
object SAMLBindings_3_4_3_b1 : SAMLBindingRefMessage()

object SAMLBindings_3_4_4_a : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1 : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_a : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_a1 : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_a2 : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_b1 : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_b2 : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_c1 : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_c2 : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_d1 : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_d2 : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_e : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_f1 : SAMLBindingRefMessage()
object SAMLBindings_3_4_4_1_f2 : SAMLBindingRefMessage()

object SAMLBindings_3_4_5_2_a1 : SAMLBindingRefMessage()

object SAMLBindings_3_4_6_a : SAMLBindingRefMessage()
object SAMLBindings_3_4_6_a1 : SAMLBindingRefMessage()
object SAMLBindings_3_5_3_a : SAMLBindingRefMessage()
object SAMLBindings_3_5_3_b : SAMLBindingRefMessage()
object SAMLBindings_3_5_4_a : SAMLBindingRefMessage()
object SAMLBindings_3_5_4_a1 : SAMLBindingRefMessage()
object SAMLBindings_3_5_4_a2 : SAMLBindingRefMessage()
object SAMLBindings_3_5_4_b : SAMLBindingRefMessage()
object SAMLBindings_3_5_4_b1 : SAMLBindingRefMessage()
object SAMLBindings_3_5_4_c : SAMLBindingRefMessage()
object SAMLBindings_3_5_4_d : SAMLBindingRefMessage()
object SAMLBindings_3_5_4_d1 : SAMLBindingRefMessage()
object SAMLBindings_3_5_4_d2 : SAMLBindingRefMessage()
object SAMLBindings_3_5_5_2_a : SAMLBindingRefMessage()
object SAMLBindings_3_5_6_a : SAMLBindingRefMessage()

//-----------------
// XML Datatype Schema
//-----------------

object XMLDatatypesSchema_3_2_7 : XmlDatatypeRefMessage()
object XMLDatatypesSchema_3_2_7_1_a : XmlDatatypeRefMessage()
object XMLDatatypesSchema_3_2_7_1_b : XmlDatatypeRefMessage()
object XMLDatatypesSchema_3_2_7_1_c : XmlDatatypeRefMessage()

//-----------------
// XML Signature Syntax and Processing
//-----------------

object XMLSignature_4_5 : XmlSigRefMessage()
