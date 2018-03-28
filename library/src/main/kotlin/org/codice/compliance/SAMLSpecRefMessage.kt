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
package org.codice.compliance

import java.util.ResourceBundle

private val bundle = ResourceBundle.getBundle("SAMLSpecRefMessage")

enum class SAMLSpecRefMessage(val message: String) {
    //-----------------
    // PROFILES
    //-----------------
    SAMLProfiles_3_1_a(bundle.getString("SAMLProfiles_3_1_a")),
    SAMLProfiles_3_1_b(bundle.getString("SAMLProfiles_3_1_b")),
    SAMLProfiles_3_1_c(bundle.getString("SAMLProfiles_3_1_c")),

    SAMLProfiles_4_1_4_2_a(bundle.getString("SAMLProfiles_4_1_4_2_a")),
    SAMLProfiles_4_1_4_2_b(bundle.getString("SAMLProfiles_4_1_4_2_b")),
    SAMLProfiles_4_1_4_2_c(bundle.getString("SAMLProfiles_4_1_4_2_c")),
    SAMLProfiles_4_1_4_2_d(bundle.getString("SAMLProfiles_4_1_4_2_d")),
    // todo SAMLProfiles_4_1_4_2e(bundle.getString("SAMLProfiles_4_1_4_2e")),
    SAMLProfiles_4_1_4_2_f(bundle.getString("SAMLProfiles_4_1_4_2_f")),
    SAMLProfiles_4_1_4_2_g(bundle.getString("SAMLProfiles_4_1_4_2_g")),
    SAMLProfiles_4_1_4_2_h(bundle.getString("SAMLProfiles_4_1_4_2_h")),
    SAMLProfiles_4_1_4_2_i(bundle.getString("SAMLProfiles_4_1_4_2_i")),
    SAMLProfiles_4_1_4_2_j(bundle.getString("SAMLProfiles_4_1_4_2_j")),
    SAMLProfiles_4_1_4_2_k(bundle.getString("SAMLProfiles_4_1_4_2_k")),

    SAMLProfiles_4_1_4_5(bundle.getString("SAMLProfiles_4_1_4_5")),

    //-----------------
    // CORE
    //-----------------
    SAMLCore_1_3_1_a(bundle.getString("SAMLCore_1_3_1_a")),

    SAMLCore_1_3_2_a(bundle.getString("SAMLCore_1_3_2_a")),

    SAMLCore_1_3_3(bundle.getString("SAMLCore_1_3_3")),

    SAMLCore_1_3_4(bundle.getString("SAMLCore_1_3_4")),

    SAMLCore_2_2_3_a(bundle.getString("SAMLCore_2_2_3_a")),
    SAMLCore_2_2_3_b(bundle.getString("SAMLCore_2_2_3_b")),

    SAMLCore_2_2_4_a(bundle.getString("SAMLCore_2_2_4_a")),
    // todo SAMLCore_2_2_4_b(bundle.getString("SAMLCore_2_2_4_b")),
    // todo SAMLCore_2_2_4_c(bundle.getString("SAMLCore_2_2_4_c")),

    SAMLCore_2_3_3_a(bundle.getString("SAMLCore_2_3_3_a")),
    SAMLCore_2_3_3_b(bundle.getString("SAMLCore_2_3_3_b")),
    SAMLCore_2_3_3_c(bundle.getString("SAMLCore_2_3_3_c")),

    SAMLCore_2_3_4_a(bundle.getString("SAMLCore_2_3_4_a")),
    // todo SAMLCore_2_3_4_b(bundle.getString("SAMLCore_2_3_4_b")),

    SAMLCore_2_4_1_2_b(bundle.getString("SAMLCore_2_4_1_2_b")),

    SAMLCore_2_4_1_3(bundle.getString("SAMLCore_2_4_1_3")),

    SAMLCore_2_5_1_a(bundle.getString("SAMLCore_2_5_1_a")),
    SAMLCore_2_5_1_b(bundle.getString("SAMLCore_2_5_1_b")),
    SAMLCore_2_5_1_c(bundle.getString("SAMLCore_2_5_1_c")),

    SAMLCore_2_5_1_2(bundle.getString("SAMLCore_2_5_1_2")),

    SAMLCore_2_5_1_5(bundle.getString("SAMLCore_2_5_1_5")),

    SAMLCore_2_5_1_6_a(bundle.getString("SAMLCore_2_5_1_6_a")),
    SAMLCore_2_5_1_6_b(bundle.getString("SAMLCore_2_5_1_6_b")),

    SAMLCore_2_7_2(bundle.getString("SAMLCore_2_7_2")),

    SAMLCore_2_7_3(bundle.getString("SAMLCore_2_7_3")),

    SAMLCore_2_7_3_1_1(bundle.getString("SAMLCore_2_7_3_1_1")),

    SAMLCore_2_7_3_2_a(bundle.getString("SAMLCore_2_7_3_2_a")),
    // todo SAMLCore_2_7_3_2_b(bundle.getString("SAMLCore_2_7_3_2_b")),

    SAMLCore_2_7_4(bundle.getString("SAMLCore_2_7_4")),

    SAMLCore_3_2_1_a(bundle.getString("SAMLCore_3_2_1_a")),
    SAMLCore_3_2_1_b(bundle.getString("SAMLCore_3_2_1_b")),
    SAMLCore_3_2_1_c(bundle.getString("SAMLCore_3_2_1_c")),

    SAMLCore_3_2_2_a(bundle.getString("SAMLCore_3_2_2_a")),
    SAMLCore_3_2_2_b(bundle.getString("SAMLCore_3_2_2_b")),
    SAMLCore_3_2_2_c(bundle.getString("SAMLCore_3_2_2_c")),
    SAMLCore_3_2_2_d(bundle.getString("SAMLCore_3_2_2_d")),
    SAMLCore_3_2_2_e(bundle.getString("SAMLCore_3_2_2_e")),

    SAMLCore_3_2_2_2(bundle.getString("SAMLCore_3_2_2_2")),
    SAMLCore_3_3_2_2_a(bundle.getString("SAMLCore_3_3_2_2_a")),
    SAMLCore_3_3_2_2_b(bundle.getString("SAMLCore_3_3_2_2_b")),

    SAMLCore_3_3_2_3(bundle.getString("SAMLCore_3_3_2_3")),

    SAMLCore_3_4(bundle.getString("SAMLCore_3_4")),

    // todo SAMLCore_3_4_1_1_a(bundle.getString("SAMLCore_3_4_1_1_a")),

    SAMLCore_3_7_1(bundle.getString("SAMLCore_3_7_1")),

    SAMLCore_5_4_1(bundle.getString("SAMLCore_5_4_1")),

    SAMLCore_5_4_2_a(bundle.getString("SAMLCore_5_4_2_a")),
    SAMLCore_5_4_2_b(bundle.getString("SAMLCore_5_4_2_b")),
    SAMLCore_5_4_2_b1(bundle.getString("SAMLCore_5_4_2_b1")),

    // todo SAMLCore_6_1_a(bundle.getString("SAMLCore_6_1_a")),
    SAMLCore_6_1_b(bundle.getString("SAMLCore_6_1_b")),

    //-----------------
    // BINDINGS
    //-----------------
    // todo SAMLBindings_3_1_1_b(bundle.getString("SAMLBindings_3_1_1_b")),

    SAMLBindings_3_1_2_1(bundle.getString("SAMLBindings_3_1_2_1")),

    SAMLBindings_3_4_3_a(bundle.getString("SAMLBindings_3_4_3_a")),
    SAMLBindings_3_4_3_b1(bundle.getString("SAMLBindings_3_4_3_b1")),

    SAMLBindings_3_4_4_a(bundle.getString("SAMLBindings_3_4_4_a")),

    SAMLBindings_3_4_4_1(bundle.getString("SAMLBindings_3_4_4_1")),
    SAMLBindings_3_4_4_1_a(bundle.getString("SAMLBindings_3_4_4_1_a")),
    SAMLBindings_3_4_4_1_a1(bundle.getString("SAMLBindings_3_4_4_1_a1")),
    SAMLBindings_3_4_4_1_a2(bundle.getString("SAMLBindings_3_4_4_1_a2")),
    // todo SAMLBindings_3_4_4_1_b(bundle.getString("SAMLBindings_3_4_4_1_b")),
    SAMLBindings_3_4_4_1_b1(bundle.getString("SAMLBindings_3_4_4_1_b1")),
    SAMLBindings_3_4_4_1_b2(bundle.getString("SAMLBindings_3_4_4_1_b2")),
    SAMLBindings_3_4_4_1_c1(bundle.getString("SAMLBindings_3_4_4_1_c1")),
    SAMLBindings_3_4_4_1_c2(bundle.getString("SAMLBindings_3_4_4_1_c2")),
    SAMLBindings_3_4_4_1_d1(bundle.getString("SAMLBindings_3_4_4_1_d1")),
    SAMLBindings_3_4_4_1_d2(bundle.getString("SAMLBindings_3_4_4_1_d2")),
    SAMLBindings_3_4_4_1_e(bundle.getString("SAMLBindings_3_4_4_1_e")),
    SAMLBindings_3_4_4_1_f1(bundle.getString("SAMLBindings_3_4_4_1_f1")),
    SAMLBindings_3_4_4_1_f2(bundle.getString("SAMLBindings_3_4_4_1_f2")),
    // todo SAMLBindings_3_4_4_1_g(bundle.getString("SAMLBindings_3_4_4_1_g")),

    SAMLBindings_3_4_5_2_a1(bundle.getString("SAMLBindings_3_4_5_2_a1")),
    // todo SAMLBindings_3_4_5_2_a2(bundle.getString("SAMLBindings_3_4_5_2_a2")),

    SAMLBindings_3_4_6_a(bundle.getString("SAMLBindings_3_4_6_a")),

    SAMLBindings_3_5_3_a(bundle.getString("SAMLBindings_3_5_3_a")),
    SAMLBindings_3_5_3_b(bundle.getString("SAMLBindings_3_5_3_b")),

    SAMLBindings_3_5_4_a(bundle.getString("SAMLBindings_3_5_4_a")),
    SAMLBindings_3_5_4_a1(bundle.getString("SAMLBindings_3_5_4_a1")),
    SAMLBindings_3_5_4_a2(bundle.getString("SAMLBindings_3_5_4_a2")),
    SAMLBindings_3_5_4_b(bundle.getString("SAMLBindings_3_5_4_b")),
    SAMLBindings_3_5_4_b1(bundle.getString("SAMLBindings_3_5_4_b1")),
    SAMLBindings_3_5_4_c(bundle.getString("SAMLBindings_3_5_4_c")),
    SAMLBindings_3_5_4_d(bundle.getString("SAMLBindings_3_5_4_d")),
    SAMLBindings_3_5_4_d1(bundle.getString("SAMLBindings_3_5_4_d1")),
    SAMLBindings_3_5_4_d2(bundle.getString("SAMLBindings_3_5_4_d2")),

    SAMLBindings_3_5_5_2_a(bundle.getString("SAMLBindings_3_5_5_2_a")),

    SAMLBindings_3_5_6_a(bundle.getString("SAMLBindings_3_5_6_a")),

    //-----------------
    // XML Datatype Schema
    //-----------------
    XMLDatatypesSchema_3_2_7(bundle.getString("XMLDatatypesSchema_3_2_7")),
    XMLDatatypesSchema_3_2_7_1_a(bundle.getString("XMLDatatypesSchema_3_2_7_1_a")),
    XMLDatatypesSchema_3_2_7_1_b(bundle.getString("XMLDatatypesSchema_3_2_7_1_b")),
    XMLDatatypesSchema_3_2_7_1_c(bundle.getString("XMLDatatypesSchema_3_2_7_1_c")),

    //-----------------
    // XML Signature Syntax and Processing
    //-----------------
    XMLSignature_4_5(bundle.getString("XMLSignature_4_5")),
}
