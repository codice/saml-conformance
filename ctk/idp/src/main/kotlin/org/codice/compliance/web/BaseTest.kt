/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.web

import io.kotlintest.extensions.TestListener
import io.kotlintest.specs.StringSpec

/**
 * The Base Test class of all tests used to inject the {@link ResultListener} instead of
 * doing so in each test.
 */
open class BaseTest : StringSpec() {
    override fun listeners(): List<TestListener> = listOf(ResultListener)
}
