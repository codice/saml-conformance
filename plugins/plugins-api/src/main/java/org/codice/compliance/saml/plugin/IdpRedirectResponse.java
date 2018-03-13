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
package org.codice.compliance.saml.plugin;

import static org.apache.cxf.rs.security.saml.sso.SSOConstants.RELAY_STATE;
import static org.apache.cxf.rs.security.saml.sso.SSOConstants.SAML_RESPONSE;
import static org.apache.cxf.rs.security.saml.sso.SSOConstants.SIGNATURE;
import static org.apache.cxf.rs.security.saml.sso.SSOConstants.SIG_ALG;

/**
 * This class is the return type for methods of the {@code IdpResponder} interface on the REDIRECT
 * Binding. An internal static builder class {@code Builder} should be used to build the {@code
 * IdpRedirectResponse object}.
 *
 * <p>The implemented {@code IdpResponder} methods should call the builder methods:
 *
 * <ul>
 *   <li>IdpRedirectResponse.Builder.httpStatusCode(int)
 *   <li>IdpRedirectResponse.Builder.url(String)
 * </ul>
 *
 * Before building the {@code IdpRedirectResponse} object.
 *
 * <p>Example usage:
 *
 * <p>
 *
 * <blockquote>
 *
 * <pre>
 *   IdpRedirectResponse.Builder builder = new IdpRedirectResponse.Builder();
 *   builder.httpStatusCode(exampleStatusCode)
 *       .url(exampleUrl);
 *   return builder.build();
 * </pre>
 *
 * </blockquote>
 */
public class IdpRedirectResponse {
  private IdpRedirectResponse() {
    extraUrlParameters = false;
  }

  public static class Builder {

    private IdpRedirectResponse idpRedirectResponse = new IdpRedirectResponse();

    // General
    public Builder httpStatusCode(int httpStatusCode) {
      idpRedirectResponse.httpStatusCode = httpStatusCode;
      return this;
    }

    public Builder url(String url) {
      idpRedirectResponse.parseAndSetUrlValues(url);
      return this;
    }

    public IdpRedirectResponse build() {
      return idpRedirectResponse;
    }
  }

  // General
  private int httpStatusCode;
  private String url;
  private String path;
  private String samlResponse;
  private String samlEncoding;
  private String sigAlg;
  private String signature;
  private String relayState;

  // Flags
  private boolean extraUrlParameters;
  private boolean isRelayStateGiven;

  @SuppressWarnings("squid:S3398" /* Method in here to simplify builder class */)
  private void parseAndSetUrlValues(String url) {
    this.url = url;

    String urlPath = url.split("\\?")[0];
    String urlParameters = url.split("\\?")[1];

    path = urlPath;

    for (String parameter : urlParameters.split("&")) {
      if (parameter.startsWith(SAML_RESPONSE + "=")) {
        samlResponse = parameter.replace(SAML_RESPONSE + "=", "");
      } else if (parameter.startsWith(SIG_ALG + "=")) {
        sigAlg = parameter.replace(SIG_ALG + "=", "");
      } else if (parameter.startsWith(SIGNATURE + "=")) {
        signature = parameter.replace(SIGNATURE + "=", "");
      } else if (parameter.startsWith(RELAY_STATE + "=")) {
        relayState = parameter.replace(RELAY_STATE + "=", "");
      } else if (parameter.startsWith("SAMLEncoding=")) {
        samlEncoding = parameter.replace("SAMLEncoding=", "");
      } else {
        extraUrlParameters = true;
      }
    }
  }

  public String getUrl() {
    return url;
  }

  public String getPath() {
    return path;
  }

  public String getSigAlg() {
    return sigAlg;
  }

  public String getSignature() {
    return signature;
  }

  public int getHttpStatusCode() {
    return httpStatusCode;
  }

  public String getSamlResponse() {
    return samlResponse;
  }

  public String getSamlEncoding() {
    return samlEncoding;
  }

  public String getRelayState() {
    return relayState;
  }

  public boolean isExtraUrlParameters() {
    return extraUrlParameters;
  }

  public boolean isRelayStateGiven() {
    return isRelayStateGiven;
  }

  public void setRelayStateGiven(boolean relayStateGiven) {
    this.isRelayStateGiven = relayStateGiven;
  }
}
