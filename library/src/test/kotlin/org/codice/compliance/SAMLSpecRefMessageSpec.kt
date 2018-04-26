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

import io.kotlintest.specs.StringSpec
import org.reflections.Reflections

class SAMLSpecRefMessageSpec : StringSpec() {
    init {
        val reflection = Reflections("org.codice.compliance")
        val messageClasses = reflection.getSubTypesOf(SAMLSpecRefMessage::class.java)

        "Message objects have corresponding property entry" {
            messageClasses.forEach { messageClass ->
                messageClass.kotlin.objectInstance?.let { message ->
                    assert(message.message.isNotBlank())
                }
            }
        }
    }
}
