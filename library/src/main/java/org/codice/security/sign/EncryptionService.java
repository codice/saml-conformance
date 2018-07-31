/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.security.sign;

import org.apache.wss4j.common.crypto.PasswordEncryptor;

public interface EncryptionService extends PasswordEncryptor {

  /**
   * Decrypts a wrapped encrypted value in the "ENC(*)" format. Inputs that are not wrapped are
   * returned as a no-op.
   *
   * @param wrappedEncryptedValue a string of the form "ENC(", followed by an encrypted value, and
   *     terminated with ")".
   * @return a decryption of the given value after removing the leading "ENC(" and trailing ")".
   */
  String decryptValue(String wrappedEncryptedValue);

  /**
   * Unwraps an encrypted value in the "ENC(*)" format. Inputs that are not wrapped are returned as
   * a no-op.
   *
   * @param wrappedEncryptedValue a string of the form "ENC(", followed by an encrypted value, and
   *     terminated with ")".
   * @return the encrypted value <b>without</b> the leading "ENC(" and trailing ")".
   */
  String unwrapEncryptedValue(String wrappedEncryptedValue);
}
