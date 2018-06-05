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
package org.codice.compliance.utils

import org.apache.wss4j.common.crypto.JasyptPasswordEncryptor
import org.apache.wss4j.common.crypto.Merlin
import org.apache.xml.security.encryption.XMLCipher
import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.codice.compliance.children
import org.codice.compliance.recursiveChildren
import org.codice.compliance.utils.TestCommon.Companion.getCurrentSPHostname
import org.w3c.dom.Document
import org.w3c.dom.Element
import org.w3c.dom.Node
import java.security.Key
import java.security.Security
import java.util.Properties

class XMLDecrypter {
    companion object {
        // One time initialization
        init {
            Security.addProvider(BouncyCastleProvider())
            org.apache.xml.security.Init.init()
        }

        private const val BC_PROVIDER = "BC"

        private val serverPrivateKey by lazy {

            val encryptionFile =
                    XMLDecrypter::class.java.classLoader.getResource(
                            "${getCurrentSPHostname()}-encryption.properties")

            checkNotNull(encryptionFile)

            val encryptionProperties = encryptionFile.openStream().use {
                Properties().apply {
                    load(it)
                }
            }

            val keystorePassword = encryptionProperties.getProperty(KEYSTORE_PASSWORD)
            val keystorePrivateKeyPassword =
                    encryptionProperties.getProperty(PRIVATE_KEY_PASSWORD)
            val keystorePrivateKeyAlias =
                    encryptionProperties.getProperty(PRIVATE_KEY_ALIAS)

            // Using Apache Merlin to read the keystore
            val merlin = Merlin(encryptionProperties,
                    ClassLoader.getSystemClassLoader(),
                    JasyptPasswordEncryptor(keystorePassword))

            merlin.getPrivateKey(keystorePrivateKeyAlias, keystorePrivateKeyPassword)
        }

        /**
         * Takes in an EncryptedID, EncryptedAssertion, or EncryptedAttribute element and returns
         * the decrypted node.
         *
         * Only supports up to one level encryption using the EncryptedKey element. In other words,
         * the data must be directly encrypted by the CTK's public key, or, if another key is used
         * to encrypt the data, that key must be encrypted using the CTK's public key and put into
         * the EncryptedData element.
         *
         * @param node An encrypted {@code Node} to be decrypted
         * @return Node The decrypted {@code Node}
         */
        @Suppress("TooGenericExceptionCaught"
                /* Decryption error handling is independent of Exception type */)
        internal fun decryptAndReplaceNode(node: Node): Node {
            // message to build up and pass at the end of the method
            val messageBuilder = StringBuilder()

            val encElement = node as Element
            val ownerDocument = node.ownerDocument
            val encData = encElement.children("EncryptedData").first() as Element

            val encKeyElements = encElement.recursiveChildren("EncryptedKey")
                    .map { it as Element }
            if (encKeyElements.isEmpty()) messageBuilder.append("No Keys could be found.\n")

            // If given KeyInfo, decrypt said key and use it. Else use the default server key.
            val encryptionKey = tryKeyDecryption(encKeyElements, ownerDocument)
                    ?: serverPrivateKey
            if (encryptionKey == serverPrivateKey)
                messageBuilder.append("No Keys could be decrypted.\n")

            val encryptionCipher = XMLCipher.getProviderInstance(BC_PROVIDER).apply {
                init(XMLCipher.DECRYPT_MODE, encryptionKey)
            }

            try {
                // Keep a reference Node, either a sibling (if it has one) or parent, of `node` in
                // order to return the decrypted version of `node`
                return if (encData.previousSibling != null) {
                    val referenceNode = encData.previousSibling
                    encryptionCipher.doFinal(ownerDocument, encData)
                    node.parentNode.replaceChild(referenceNode.nextSibling, node)
                } else {
                    val referenceNode = encData.parentNode
                    encryptionCipher.doFinal(ownerDocument, encData)
                    node.parentNode.replaceChild(referenceNode.firstChild, node)
                }
            } catch (e: Exception) {
                messageBuilder.append("The data could not be decrypted.")
                throw XMLDecryptorException(messageBuilder.toString(), e)
            }
        }

        @Suppress("TooGenericExceptionCaught"
                /* Decryption error handling is independent of Exception type */)
        private fun tryKeyDecryption(encKeyElements: List<Element>,
                                     ownerDocument: Document?): Key? {

            val cipher = XMLCipher.getInstance().apply {
                init(XMLCipher.DECRYPT_MODE, null)
            }
            val keyCipher = XMLCipher.getProviderInstance(BC_PROVIDER).apply {
                init(XMLCipher.UNWRAP_MODE, serverPrivateKey)
            }

            encKeyElements.forEach {
                val encryptedKey = cipher.loadEncryptedKey(ownerDocument, it)

                try {
                    return keyCipher.decryptKey(
                            encryptedKey,
                            encryptedKey.encryptionMethod.algorithm)
                } catch (e: Exception) {
                    // Continue the loop. Keep trying. Don't give up.
                }
            }
            return null // Give up.
        }

        /**
         * Custom exception. Used to store the custom error message built during decryption.
         *
         * @param message A message built by the decryptor to accompany the exception
         * @param cause An optional cause
         */
        class XMLDecryptorException(
                override val message: String,
                override val cause: Throwable? = null) :
                RuntimeException(message, cause)
    }
}
