package org.codice.security.sign;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.zip.Inflater;
import java.util.zip.InflaterInputStream;
import org.apache.cxf.helpers.IOUtils;

public class Decoder {

  private static final boolean GZIP_COMPATIBLE = true;

  private Decoder() {}

  /**
   * Base 64 decodes POST SAML messages
   * @param message - SAML POST message
   * @return - decoded message
   */
  public static String decodePostMessage(String message) throws UnsupportedEncodingException {
    return URLDecoder.decode(new String(Base64.getDecoder().decode(message.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8.name());
  }

  /**
   * URL decodes, base 64 decodes and inflates Redirect SAML messages
   * @param message - SAML Redirect message
   * @return - decoded message
   */
  public static String decodeRedirectMessage(String message) throws IOException {
    String urlDecoded = URLDecoder.decode(message, StandardCharsets.UTF_8.name());
    byte[] deflatedValue = Base64.getDecoder().decode(urlDecoded.getBytes(StandardCharsets.UTF_8));
    InputStream is =
        new InflaterInputStream(
            new ByteArrayInputStream(deflatedValue), new Inflater(GZIP_COMPATIBLE));
    return IOUtils.toString(is, StandardCharsets.UTF_8.name());
  }
}
