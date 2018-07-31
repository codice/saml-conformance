/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.verification.core

import org.codice.compliance.verification.core.assertions.AssertionsVerifier
import org.codice.compliance.verification.core.assertions.ConditionsVerifier
import org.codice.compliance.verification.core.assertions.NameIdentifierVerifier
import org.codice.compliance.verification.core.assertions.StatementVerifier
import org.codice.compliance.verification.core.assertions.SubjectVerifier
import org.w3c.dom.Node

class SamlAssertionsVerifier(val node: Node) {

    /** 2 SAML Assertions */
    fun verify() {
        NameIdentifierVerifier(node).verify()
        AssertionsVerifier(node).verify()
        SubjectVerifier(node).verify()
        ConditionsVerifier(node).verify()
        StatementVerifier(node).verify()
    }
}
