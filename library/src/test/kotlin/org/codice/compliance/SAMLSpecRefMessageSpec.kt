/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
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
