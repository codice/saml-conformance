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
package io.kotlintest.provided

import de.jupf.staticlog.Log
import io.kotlintest.AbstractProjectConfig
import io.kotlintest.Description
import io.kotlintest.Tag
import io.kotlintest.TestResult
import io.kotlintest.extensions.TestListener
import io.restassured.RestAssured
import io.restassured.RestAssured.config
import io.restassured.config.RedirectConfig.redirectConfig
import org.codice.compliance.Common
import org.codice.compliance.utils.GlobalSession
import org.codice.compliance.utils.TestCommon.Companion.useDefaultServiceProvider

object SLO : Tag()
object SSO : Tag()

object ProjectConfig : AbstractProjectConfig() {
    override fun listeners(): List<TestListener> = listOf(GlobalSession, SPReset)

    override fun beforeAll() {
        RestAssured.config = config().redirect(redirectConfig().followRedirects(false))

        val setOfExclusions = mutableSetOf<Tag>()

        if (Common.idpMetadataObject.descriptor?.singleSignOnServices?.isEmpty() == true) {
            Log.warn("SSO endpoints were not found in the IdP's metadata. " +
                "Disabling SSO and SLO tests.")
            setOfExclusions.apply {
                add(SSO)
                add(SLO)
            }
        }

        if (Common.idpMetadataObject.descriptor?.singleLogoutServices?.isEmpty() == true) {
            Log.warn("SSO endpoints were not found in the IdP's metadata. " +
                "Disabling SLO tests.")
            setOfExclusions.add(SLO)
        }

        System.setProperty("kotlintest.tags.exclude",
            setOfExclusions.joinToString(",", transform = { it.name }))
    }
}

object SPReset : TestListener {
    override fun afterTest(description: Description, testResult: TestResult) {
        useDefaultServiceProvider()
    }
}
