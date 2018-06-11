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
package org.codice.compliance.utils

import io.kotlintest.Description
import io.kotlintest.extensions.TestListener
import io.restassured.filter.cookie.CookieFilter
import io.restassured.specification.RequestSpecification
import org.codice.compliance.utils.GlobalSession.globalCookieFilter

object GlobalSession : TestListener {
    private val globalCookies: MutableMap<String, String> = mutableMapOf()
    lateinit var globalCookieFilter: CookieFilter
        private set

    fun addCookies(cookies: Map<String, String>) {
        globalCookies.putAll(cookies)
    }
    fun getCookies(): Map<String, String> = globalCookies

    override fun beforeTest(description: Description) {
        globalCookies.clear()
        globalCookieFilter = CookieFilter()
    }
}

fun RequestSpecification.usingTheGlobalHttpSession(): RequestSpecification {
    return this.apply {
        filter(globalCookieFilter)
        cookies(GlobalSession.getCookies())
    }
}
