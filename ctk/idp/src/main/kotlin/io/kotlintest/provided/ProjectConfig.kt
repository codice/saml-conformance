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

import io.kotlintest.AbstractProjectConfig
import io.kotlintest.extensions.TestListener
import io.restassured.RestAssured
import io.restassured.RestAssured.config
import io.restassured.config.RedirectConfig.redirectConfig
import org.codice.compliance.utils.GlobalSession

object ProjectConfig : AbstractProjectConfig() {
    override fun listeners(): List<TestListener> = listOf(GlobalSession)

    override fun beforeAll() {
        RestAssured.config = config().redirect(redirectConfig().followRedirects(false))
    }
}
