/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.security.sign;

import java.io.File;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.keyczar.Crypter;
import org.keyczar.KeyczarTool;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class EncryptionServiceImpl implements EncryptionService {

  private static final Logger LOGGER = LoggerFactory.getLogger(EncryptionServiceImpl.class);

  private static final Pattern ENC_PATTERN = Pattern.compile("^ENC\\((.*)\\)$");

  private final Crypter crypter;

  public EncryptionServiceImpl() {
    String passwordDirectory = this.getClass().getClassLoader().getResource("certs").getPath();

    synchronized (EncryptionServiceImpl.class) {
      if (!new File(passwordDirectory.concat("/meta")).exists()) {
        KeyczarTool.main(
            new String[] {
              "create", "--location=" + passwordDirectory, "--purpose=crypt", "--name=Password"
            });
        KeyczarTool.main(
            new String[] {"addkey", "--location=" + passwordDirectory, "--status=primary"});
      }
      Crypter newCrypter = null;
      try {
        newCrypter = new Crypter(passwordDirectory);
      } catch (Exception e) {
        LOGGER.debug(e.getMessage());
      }
      this.crypter = newCrypter;
    }
  }

  /**
   * Encrypts a plain text value using Keyczar.
   *
   * @param plainTextValue The value to encrypt.
   */
  @Override
  public synchronized String encrypt(String plainTextValue) {
    try {
      return crypter.encrypt(plainTextValue);
    } catch (Exception e) {
      LOGGER.debug("Key and encryption service failed to set up. Failed to encrypt.", e);
      return plainTextValue;
    }
  }

  /**
   * Decrypts a plain text value using Keyczar
   *
   * @param encryptedValue The value to decrypt.
   */
  @Override
  public synchronized String decrypt(String encryptedValue) {
    try {
      return crypter.decrypt(encryptedValue);
    } catch (Exception e) {
      LOGGER.debug("Key and encryption service failed to set up. Failed to decrypt.", e);
      return encryptedValue;
    }
  }

  // @formatter:off

  /**
   * {@inheritDoc}
   *
   * <pre>{@code
   * One can encrypt passwords using the security:encrypt console command.
   *
   * user@local>security:encrypt secret
   * c+GitDfYAMTDRESXSDDsMw==
   *
   * A wrapped encrypted password is wrapped in ENC() as follows: ENC(HsOcGt8seSKc34sRUYpakQ==)
   *
   * }</pre>
   */
  // @formatter:on
  @Override
  public String decryptValue(String wrappedEncryptedValue) {
    String encryptedValue = unwrapEncryptedValue(wrappedEncryptedValue);
    if (wrappedEncryptedValue == null) {
      LOGGER.debug("A null password was provided.");
      return null;
    }
    if (wrappedEncryptedValue.isEmpty()) {
      LOGGER.debug("A blank password was provided in the configuration.");
      return "";
    }
    // If the password is not in the form ENC(my-encrypted-password),
    // we assume the password is not encrypted.
    if (wrappedEncryptedValue.equals(encryptedValue)) {
      return wrappedEncryptedValue;
    }
    LOGGER.debug("Unwrapped encrypted password is now being decrypted");
    return decrypt(encryptedValue);
  }

  /**
   * {@inheritDoc}
   *
   * <p>Given a string that starts with 'ENC(' and ends with ')', returns the in-between substring.
   * This method is meant to remove the wrapping notation for encrypted values, typically passwords.
   *
   * <p>If the input is a password and is not in the form ENC(my-encrypted-password), we assume the
   * password is not encrypted.
   *
   * @param wrappedEncryptedValue The wrapped encrypted value, in the form
   *     'ENC(my-encrypted-value)'.
   * @return The value within the parenthesis.
   */
  @Override
  public String unwrapEncryptedValue(String wrappedEncryptedValue) {
    if (wrappedEncryptedValue == null) {
      LOGGER.debug("You have provided a null password in your configuration.");
      return null;
    }

    // Get the value in parenthesis. In this example, ENC(my-encrypted-password),
    // m.group(1) would return my-encrypted-password.
    Matcher m = ENC_PATTERN.matcher(wrappedEncryptedValue);
    if (m.find()) {
      LOGGER.debug("Wrapped encrypted password value found.");
      return m.group(1);
    }
    return wrappedEncryptedValue;
  }
}
