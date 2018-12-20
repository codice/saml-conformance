/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance

import io.kotlintest.specs.StringSpec

class LoggingSpec : StringSpec() {
    companion object {
        private const val EXAMPLE_PACKAGE = "example.package"
        private const val WILDCARD_EXAMPLE_PACKAGE = "example.*"
        private const val SHORT_EXAMPLE_PACKAGE = "example"
        private const val LONG_EXAMPLE_PACKAGE = "example.package.long"
        private const val DIFFERENT_EXAMPLE_PACKAGE = "different.package"
        private const val MULTIPLE_EXAMPLE_PACKAGE = "multiple.package"
        private const val MULTIPLE_PACKAGES = "$EXAMPLE_PACKAGE;$MULTIPLE_EXAMPLE_PACKAGE"
    }
    init {
        "No debug option" {
            System.clearProperty(DEBUG_PACKAGES)
            assert(isPackageInDebugList(EXAMPLE_PACKAGE)) { "Should match all packages" }
        }

        "Empty debug option given" {
            System.setProperty(DEBUG_PACKAGES, "")

            assert(isPackageInDebugList(EXAMPLE_PACKAGE)) { "Should match all packages" }

            System.clearProperty(DEBUG_PACKAGES)
        }

        "Debug option given with single package" {
            System.setProperty(DEBUG_PACKAGES, EXAMPLE_PACKAGE)

            assert(isPackageInDebugList(EXAMPLE_PACKAGE),
            { "$EXAMPLE_PACKAGE should match $EXAMPLE_PACKAGE package" })

            System.clearProperty(DEBUG_PACKAGES)
        }

        "Debug option given with wildcard package" {
            System.setProperty(DEBUG_PACKAGES, WILDCARD_EXAMPLE_PACKAGE)

            assert(isPackageInDebugList(EXAMPLE_PACKAGE),
            { "$WILDCARD_EXAMPLE_PACKAGE should match $EXAMPLE_PACKAGE package" })

            System.clearProperty(DEBUG_PACKAGES)
        }

        "Debug option given with short package" {
            System.setProperty(DEBUG_PACKAGES, SHORT_EXAMPLE_PACKAGE)

            assert(isPackageInDebugList(EXAMPLE_PACKAGE),
            { "$SHORT_EXAMPLE_PACKAGE should match $EXAMPLE_PACKAGE package" })

            System.clearProperty(DEBUG_PACKAGES)
        }

        "Debug option given with long package" {
            System.setProperty(DEBUG_PACKAGES, LONG_EXAMPLE_PACKAGE)

            assert(!isPackageInDebugList(EXAMPLE_PACKAGE),
            { "$LONG_EXAMPLE_PACKAGE should not match $EXAMPLE_PACKAGE package" })

            System.clearProperty(DEBUG_PACKAGES)
        }

        "Debug option given with different package" {
            System.setProperty(DEBUG_PACKAGES, DIFFERENT_EXAMPLE_PACKAGE)

            assert(!isPackageInDebugList(EXAMPLE_PACKAGE),
            { "$DIFFERENT_EXAMPLE_PACKAGE should not match $EXAMPLE_PACKAGE package" })

            System.clearProperty(DEBUG_PACKAGES)
        }

        "Debug option given with multiple packages" {
            System.setProperty(DEBUG_PACKAGES, MULTIPLE_PACKAGES)

            assert(isPackageInDebugList(EXAMPLE_PACKAGE),
            { "$MULTIPLE_PACKAGES should match $EXAMPLE_PACKAGE" })

            assert(isPackageInDebugList(MULTIPLE_EXAMPLE_PACKAGE),
            { "$MULTIPLE_PACKAGES should match $MULTIPLE_EXAMPLE_PACKAGE" })

            assert(!isPackageInDebugList(DIFFERENT_EXAMPLE_PACKAGE),
            { "$MULTIPLE_PACKAGES should not match $DIFFERENT_EXAMPLE_PACKAGE" })

            System.clearProperty(DEBUG_PACKAGES)
        }

        // test debugWithSupplier and debugPrettyPrintXml (TODO)
    }
}
