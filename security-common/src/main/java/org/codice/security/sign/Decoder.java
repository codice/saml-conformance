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

  private Decoder() {
  }

  /**
   * URL decodes and base 64 decodes POST SAML messages
   *
   * @param message - SAML POST message
   * @return - decoded message
   */
  public static String decodePostMessage(String message) throws UnsupportedEncodingException {
    return URLDecoder
        .decode(new String(Base64.getDecoder().decode(message.getBytes(StandardCharsets.UTF_8))),
            StandardCharsets.UTF_8.name());
  }

  /**
   * URL decodes, base 64 decodes and inflates Redirect SAML messages
   *
   * @param message - SAML Redirect message
   * @return - decoded message
   */
  public static String decodeRedirectMessage(String message) throws UnsupportedEncodingException {
      String urlDecoded = URLDecoder.decode(message, StandardCharsets.UTF_8.name());
      byte[] deflatedValue = Base64.getDecoder().decode(urlDecoded.getBytes(StandardCharsets.UTF_8));
      InputStream is =
              new InflaterInputStream(
                      new ByteArrayInputStream(deflatedValue), new Inflater(GZIP_COMPATIBLE));
      try {
      return IOUtils.toString(is, StandardCharsets.UTF_8.name());
    } catch (IOException e) { // catch and return a different exception for more specific error handling
        throw new IllegalArgumentException();
    }
  }
}
