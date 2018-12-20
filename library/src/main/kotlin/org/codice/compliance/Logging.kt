/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance

import de.jupf.staticlog.Log
import de.jupf.staticlog.core.LogLevel
import kotlin.test.currentStackTrace

fun Log.debugWithSupplier(
    callSite: StackTraceElement = currentStackTrace()[1],
    message: () -> String
) {
    val packageName = callSite.className.substringBeforeLast(".")
    if (this.logLevel == LogLevel.DEBUG && isPackageInDebugList(packageName)) {
        this.debug("${message()} [(${callSite.className}:${callSite.lineNumber})]")
    }
}

fun String.debugPrettyPrintXml(header: String?) {
    Log.debugWithSupplier(currentStackTrace()[1]) {
        val headerVal = if (header != null) "$header:\n\n" else ""
        "$headerVal ${this.prettyPrintXml()}"
    }
}

// visible for testing
internal fun isPackageInDebugList(packageName: String): Boolean {
    val debugLoggingPackageListRegex = debugLoggingPackageListRegex()
    return if (debugLoggingPackageListRegex.isEmpty()) true // using debug as a flag
    else debugLoggingPackageListRegex.any { debugPackageNameRegex ->
        packageName.matches((debugPackageNameRegex).toRegex()) ||
        packageName.matches(("$debugPackageNameRegex.*").toRegex()) // match sub packages
    }
}

private fun debugLoggingPackageListRegex(): List<String> {
    return System.getProperty(DEBUG_PACKAGES).let { property ->
        // short circuit if system property is not changed (cannot use lazy because unit tests)
        if (property == oldDebugPackagesProperty) oldDebugLoggingPackageListRegex
        else {
            val packageList: ArrayList<String> = ArrayList(property.split(";"))
            packageList.forEachIndexed { index, _ ->
                // Escape the "." characters to avoid regex issues
                packageList[index].replace(".", "\\.")
                // Modify the "*" wildcard to match anything
                packageList[index].replace("*", ".*")
            }

            oldDebugPackagesProperty = property
            oldDebugLoggingPackageListRegex = packageList
            packageList
        }
    }
}

private var oldDebugLoggingPackageListRegex: List<String> = ArrayList()
private var oldDebugPackagesProperty: String? = null
