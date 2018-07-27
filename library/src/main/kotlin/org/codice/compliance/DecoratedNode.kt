/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance

import org.w3c.dom.Node

interface DecoratedNode {
    fun getNode(): Node
}
