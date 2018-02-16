package org.codice.security.sign;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.Deflater;
import java.util.zip.DeflaterOutputStream;

public class Encoder {

  private static final boolean GZIP_COMPATIBLE = true;

  private Encoder() {}

  /**
   * Base 64 decodes then URL encodes POST SAML messages
   * @param message - SAML POST message
   * @return - decoded message
   */
  public static String encodePostMessage(String message) throws IOException {
    return "SAMLRequest=" + URLEncoder.encode(Base64.getEncoder().encodeToString(message.getBytes(StandardCharsets.UTF_8)), StandardCharsets.UTF_8.name());
  }

  /**
   * Deflates, base 64 encodes then URL encodes Redirect SAML messages
   * @param message - SAML Redirect message
   * @return - encoded message
   */
  public static String encodeRedirectMessage(String message) throws IOException {
    ByteArrayOutputStream valueBytes = new ByteArrayOutputStream();
    try (OutputStream tokenStream =
        new DeflaterOutputStream(valueBytes, new Deflater(Deflater.DEFLATED, GZIP_COMPATIBLE))) {
      tokenStream.write(message.getBytes(StandardCharsets.UTF_8));
      tokenStream.close();

      String encodedMessage = Base64.getEncoder().encodeToString(valueBytes.toByteArray());
      return URLEncoder.encode(encodedMessage, StandardCharsets.UTF_8.name());
    }
  }
}
