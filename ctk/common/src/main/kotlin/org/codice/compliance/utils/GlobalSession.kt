/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
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
