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

import org.w3c.dom.Node
import org.w3c.dom.NodeList
import java.io.StringWriter
import javax.xml.transform.dom.DOMSource
import javax.xml.transform.stream.StreamResult
import javax.xml.xpath.XPathConstants
import javax.xml.xpath.XPathFactory

/**
 * Finds all of the first level children of a {@code Node}.
 *
 * @param name - Optional element name to match.
 * @return List of child {@code Nodes}.
 */
fun Node.children(name: String? = null): List<Node> {
    val predicate: (Node) -> Boolean =
            if (name == null) {
                { true }
            } else {
                { it.localName == name }
            }

    return ((this.childNodes.length - 1) downTo 0)
            .map { this.childNodes.item(it) }
            .filter(predicate)
            .toList()
}

/**
 * Finds all of the children of a {@code Node}, regardless of how deep an element is nested in its
 * children.
 *
 * @param name - Optional element name to match.
 * @return List of child {@code Nodes}.
 */
fun Node.recursiveChildren(name: String? = null): List<Node> {
    val nodes = mutableListOf<Node>()
    this.children().forEach {
        if (name == null || name == it.localName) nodes.add(it)
        nodes.addAll(it.recursiveChildren(name))
    }
    return nodes
}

/**
 * Finds all of the siblings of a {@code Node}.
 *
 * @param name - Optional element name to match.
 * @return List of sibling {code Nodes}.
 */
fun Node.siblings(name: String? = null): List<Node> {
    val siblingNodes = mutableListOf<Node>()

    // backwards portion
    var tempNode = this
    while (tempNode.previousSibling != null) {
        tempNode = tempNode.previousSibling
        if (name == null || tempNode.localName == name)
            siblingNodes.add(tempNode)
    }

    // forwards portion
    tempNode = this
    while (tempNode.nextSibling != null) {
        tempNode = tempNode.nextSibling
        if (name == null || tempNode.localName == name)
            siblingNodes.add(tempNode)
    }

    return siblingNodes
}

/**
 * Returns all of the attributes of a {@code Node} as a {@code List} of {@code Nodes}.
 */
fun Node.attributeList(): List<Node> {
    val attributesList = mutableListOf<Node>()
    this.attributes?.let {
        for (i in it.length - 1 downTo 0) {
            attributesList.add(it.item(i))
        }
    }
    return attributesList
}

fun Node.prettyPrintXml(): String {
    // Remove whitespaces outside tags
    normalize()
    val thisNode = if (this is DecoratedNode)
        this.getNode()
    else
        this

    val xPath = XPathFactory.newInstance().newXPath()
    val nodeList = xPath.evaluate("//text()[normalize-space()='']",
            thisNode,
            XPathConstants.NODESET) as NodeList
    for (i in 0 until nodeList.length) {
        val node = nodeList.item(i)
        node.parentNode.removeChild(node)
    }

    val transformer = createTransformer()
    val output = StringWriter()
    transformer.transform(DOMSource(thisNode), StreamResult(output))
    return output.toString()
}

/**
 * Returns the named attribute node, or null if not present.
 */
fun Node.attributeNode(name: String) = this.attributes?.getNamedItem(name)

/**
 * Returns the named attribute node, or null if not present.
 */
fun Node.attributeNodeNS(ns: String, name: String) = this.attributes?.getNamedItemNS(ns, name)

/**
 * Returns the text content of the attribute of this node, or null if not present.
 */
fun Node.attributeText(name: String) = attributeNode(name)?.textContent

/**
 * Returns the text content of the attribute of this node, or null if not present.
 */
fun Node.attributeTextNS(ns: String, name: String) = attributeNodeNS(ns, name)?.textContent
