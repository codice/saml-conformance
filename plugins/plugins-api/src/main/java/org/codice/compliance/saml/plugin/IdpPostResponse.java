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

import com.jayway.restassured.path.xml.element.Node;

/**
 * This class is the return type for methods of the {@code IdpResponder} interface for the POST
 * Binding. An internal static builder class {@code Builder} should be used to build the {@code
 * IdpPostResponse} object.
 *
 * <p>The implemented {@code IdpResponder} methods should call the builder methods:
 *
 * <ul>
 *   <li>IdpPostResponse.Builder.httpStatusCode(int)
 *   <li>BIdpPostResponse.Builder.samlForm(Node)
 * </ul>
 *
 * Before building the {@code IdpPostResponse} object.
 *
 * <p>Example usage:
 *
 * <p>
 *
 * <blockquote>
 *
 * <pre>
 *   IdpPostResponse.Builder builder = new IdpPostResponse.Builder();
 *   builder.httpStatusCode(exampleStatusCode)
 *       .samlForm(exampleSamlForm);
 *   return builder.build();
 * </pre>
 *
 * </blockquote>
 */
public class IdpPostResponse {
  private IdpPostResponse() {}

  public static class Builder {

    private IdpPostResponse idpPostResponse = new IdpPostResponse();

    // General
    public Builder httpStatusCode(int httpStatusCode) {
      idpPostResponse.httpStatusCode = httpStatusCode;
      return this;
    }

    public Builder samlForm(Node samlResponseForm) {
      idpPostResponse.parseAndSetFormValues(samlResponseForm);
      return this;
    }

    public IdpPostResponse build() {
      return idpPostResponse;
    }
  }

  // General
  private int httpStatusCode;
  private Node samlResponseForm;
  private String samlResponse;
  private String relayState;

  // Flags
  private boolean isRelayStateHidden;
  private boolean isRelayStateGiven;

  @SuppressWarnings("squid:S3398" /* Method in here to simplify builder class */)
  private void parseAndSetFormValues(Node samlResponseForm) {
    this.samlResponseForm = samlResponseForm;

    // Bindings 3.5.4 "If the message is a SAML response, then the form control MUST be named
    // SAMLResponse."
    samlResponse =
        samlResponseForm
            .getNodes("input")
            .stream()
            .filter(node -> node.name().equals(SAML_RESPONSE))
            .map(Node::value)
            .findFirst()
            .orElse(null);

    Node relayStateNode =
        samlResponseForm
            .getNodes("input")
            .stream()
            .filter(node -> node.name().equals(RELAY_STATE))
            .findFirst()
            .orElse(null);

    // Bindings 3.5.4 "If a “RelayState” value is to accompany the SAML protocol message, it MUST be
    // placed in an additional hidden form control named RelayState within the same form with the
    // SAML message"
    if (relayStateNode != null) {
      relayState = relayStateNode.value();
      if (relayStateNode.getAttribute("type") != null) {
        isRelayStateHidden = relayStateNode.getAttribute("type").equals("hidden");
      }
    }
  }

  public int getHttpStatusCode() {
    return httpStatusCode;
  }

  public String getSamlResponse() {
    return samlResponse;
  }

  public String getRelayState() {
    return relayState;
  }

  public Node getSamlResponseForm() {
    return samlResponseForm;
  }

  public boolean isRelayStateHidden() {
    return isRelayStateHidden;
  }

  public boolean isRelayStateGiven() {
    return isRelayStateGiven;
  }

  public void setRelayStateGiven(boolean relayStateGiven) {
    this.isRelayStateGiven = relayStateGiven;
  }
}
