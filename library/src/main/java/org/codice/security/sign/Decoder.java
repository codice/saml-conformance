/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
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
import org.codice.security.sign.Decoder.DecoderException.InflErrorCode;

public class Decoder {

  private static final boolean GZIP_COMPATIBLE = true;

  private Decoder() {}

  /**
   * URL decodes and base 64 decodes POST SAML messages
   *
   * @param message - SAML POST message
   * @return - decoded message
   */
  public static String decodePostMessage(String message) throws DecoderException {
    try {
      return new String(
          Base64.getDecoder().decode(message.getBytes(StandardCharsets.UTF_8)),
          StandardCharsets.UTF_8.name());
    } catch (UnsupportedEncodingException e) {
      throw new DecoderException(DecoderException.InflErrorCode.ERROR_BASE64_DECODING);
    }
  }

  /**
   * URL decodes, base 64 decodes and inflates Redirect SAML messages
   *
   * @param message - SAML Redirect message
   * @return - decoded message
   */
  public static String decodeAndInflateRedirectMessage(String message) throws DecoderException {
    String urlDecoded;

    try {
      urlDecoded = URLDecoder.decode(message, StandardCharsets.UTF_8.name());
    } catch (UnsupportedEncodingException e) {
      throw new DecoderException(DecoderException.InflErrorCode.ERROR_URL_DECODING);
    }

    if (urlDecoded.matches("[ \\t\\n\\x0B\\f\\r]+")) {
      throw new DecoderException(DecoderException.InflErrorCode.LINEFEED_OR_WHITESPACE);
    }

    byte[] base64Decoded = Base64.getDecoder().decode(urlDecoded.getBytes(StandardCharsets.UTF_8));
    // this method is only here to try and catch a base64 decoding error
    try {
      new String(base64Decoded, StandardCharsets.UTF_8.name());
    } catch (UnsupportedEncodingException e) {
      throw new DecoderException(InflErrorCode.ERROR_BASE64_DECODING);
    }

    InputStream is =
        new InflaterInputStream(
            new ByteArrayInputStream(base64Decoded), new Inflater(GZIP_COMPATIBLE));

    try {
      return IOUtils.toString(is, StandardCharsets.UTF_8.name());
    } catch (IOException e) {
      throw new DecoderException(DecoderException.InflErrorCode.ERROR_INFLATING);
    }
  }

  public static class DecoderException extends Exception {

    public enum InflErrorCode {
      ERROR_BASE64_DECODING,
      ERROR_URL_DECODING,
      LINEFEED_OR_WHITESPACE,
      ERROR_INFLATING
    }

    final InflErrorCode inflErrorCode;

    public DecoderException(InflErrorCode inflErrorCode) {
      super();
      this.inflErrorCode = inflErrorCode;
    }

    public InflErrorCode getInflErrorCode() {
      return inflErrorCode;
    }
  }
}
