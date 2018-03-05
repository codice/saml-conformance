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

  private Encoder() {
  }

  /**
   * Base 64 then URL encodes POST SAML messages
   *
   * @param message - SAML POST message
   * @return - decoded message
   */
  public static String encodePostMessage(String message) throws IOException {
    return "SAMLRequest=" + URLEncoder
        .encode(Base64.getEncoder().encodeToString(message.getBytes(StandardCharsets.UTF_8)),
            StandardCharsets.UTF_8.name());
  }

  /**
   * Base 64 encodes the SAML message then URL encodes it with the Relay State
   *
   * @param message - SAML POST message
   * @param relayState - Relay State to URL encode with message
   * @return - decoded message
   */
  public static String encodePostMessage(String message, String relayState) throws IOException {
    return String.format("RelayState=%s&SAMLRequest=%s",
        URLEncoder.encode(relayState, StandardCharsets.UTF_8.name()),
        URLEncoder
            .encode(Base64.getEncoder().encodeToString(message.getBytes(StandardCharsets.UTF_8)),
                StandardCharsets.UTF_8.name()));
  }

  /**
   * Deflates, base 64 encodes then URL encodes Redirect SAML messages
   *
   * @param message - SAML Redirect message
   * @return - encoded message
   */
  @SuppressWarnings("squid:S4087" /* Close call needed */)
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
