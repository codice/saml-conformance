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
package org.codice.security.saml;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

public class SamlProtocol {

  public static final String SUPPORTED_PROTOCOL = "urn:oasis:names:tc:SAML:2.0:protocol";

  public static final String REDIRECT_BINDING =
      "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect";

  public static final String SOAP_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:SOAP";

  public static final String PAOS_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:PAOS";

  public static final String POST_BINDING = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";

  public static Duration getCacheDuration() {
    return Duration.parse(
        System.getProperty("org.codice.ddf.security.saml.Metadata.cacheDuration", "P7D"));
  }

  public enum Binding {
    HTTP_POST(POST_BINDING),
    HTTP_REDIRECT(REDIRECT_BINDING),
    HTTP_ARTIFACT(SOAP_BINDING),
    SOAP(SOAP_BINDING),
    PAOS(PAOS_BINDING);

    private static Map<String, Binding> stringToBinding = new HashMap<>();

    static {
      for (Binding binding : Binding.values()) {
        stringToBinding.put(binding.getUri(), binding);
      }
    }

    private final String uri;

    Binding(String uri) {
      this.uri = uri;
    }

    public static Binding from(String value) {
      return stringToBinding.get(value);
    }

    public String getUri() {
      return uri;
    }

    public boolean isEqual(String uri) {
      return this.uri.equals(uri);
    }
  }
}
