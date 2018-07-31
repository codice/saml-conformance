/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.utils.sign;

import java.io.IOException;
import java.util.Properties;
import org.apache.commons.lang3.StringUtils;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoFactory;
import org.apache.wss4j.common.crypto.Merlin;
import org.apache.wss4j.common.crypto.PasswordEncryptor;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SystemCrypto {

  private static final Logger LOGGER = LoggerFactory.getLogger(SystemCrypto.class);

  private final PasswordEncryptor passwordEncryption;

  private final Crypto signatureCrypto;

  private final String signaturePassword;

  private final String signatureAlias;

  private final Crypto encryptionCrypto;

  private final String encryptionPassword;

  private final String encryptionAlias;

  public SystemCrypto(String hostname) throws IOException {
    this.passwordEncryption = null;
    // new EncryptionServiceImpl()

    Properties sigProperties = createProperty(String.format("%s-signature.properties", hostname));
    signatureCrypto = createCrypto(sigProperties);
    signaturePassword = getPassword(sigProperties);
    signatureAlias = getAlias(signatureCrypto, sigProperties);

    Properties encProperties = createProperty(String.format("%s-encryption.properties", hostname));
    encryptionCrypto = createCrypto(encProperties);
    encryptionPassword = getPassword(encProperties);
    encryptionAlias = getAlias(encryptionCrypto, encProperties);
  }

  private Properties createProperty(String resourceName) throws IOException {
    Properties properties = new Properties();
    properties.load(this.getClass().getClassLoader().getResource(resourceName).openStream());
    return properties;
  }

  private String getAlias(Crypto crypto, Properties cryptoProperties) {
    String user = cryptoProperties.getProperty(Merlin.PREFIX + Merlin.KEYSTORE_ALIAS);

    if (user == null) {
      try {
        user = crypto.getDefaultX509Identifier();
      } catch (WSSecurityException e) {
        LOGGER.debug("Error in getting Crypto user: ", e);
      }
    }

    return user;
  }

  private Crypto createCrypto(Properties cryptoProperties) {
    Crypto crypto = null;
    try {
      crypto =
          CryptoFactory.getInstance(
              cryptoProperties, SystemCrypto.class.getClassLoader(), passwordEncryption);
      if (crypto == null) {
        throw new IllegalStateException(
            "Error getting the Crypto instance. There is an issue with the system configuration");
      }
    } catch (WSSecurityException e) {
      throw new IllegalStateException(
          "Error getting the Crypto instance. There is an issue with the system configuration", e);
    }

    return crypto;
  }

  private String getPassword(Properties cryptoProperties) {
    String password =
        cryptoProperties.getProperty(Merlin.PREFIX + Merlin.KEYSTORE_PRIVATE_PASSWORD);

    if (password == null) {
      password = cryptoProperties.getProperty(Merlin.OLD_PREFIX + Merlin.KEYSTORE_PRIVATE_PASSWORD);
    }

    if (password != null) {
      password = decryptPassword(password.trim());
    }

    return password;
  }

  private String decryptPassword(String password) {
    if (password.startsWith(Merlin.ENCRYPTED_PASSWORD_PREFIX)
        && password.endsWith(Merlin.ENCRYPTED_PASSWORD_SUFFIX)) {
      return passwordEncryption.decrypt(
          StringUtils.substringBetween(
              password, Merlin.ENCRYPTED_PASSWORD_PREFIX, Merlin.ENCRYPTED_PASSWORD_SUFFIX));
    }

    return password;
  }

  public Crypto getSignatureCrypto() {
    return signatureCrypto;
  }

  public String getSignaturePassword() {
    return signaturePassword;
  }

  public Crypto getEncryptionCrypto() {
    return encryptionCrypto;
  }

  public String getEncryptionPassword() {
    return encryptionPassword;
  }

  public String getSignatureAlias() {
    return signatureAlias;
  }

  public String getEncryptionAlias() {
    return encryptionAlias;
  }
}
