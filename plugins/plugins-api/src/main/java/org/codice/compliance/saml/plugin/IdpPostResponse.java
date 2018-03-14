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

import static org.apache.commons.lang3.StringUtils.isNotEmpty;
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
public class IdpPostResponse extends IdpResponse {

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

  private static final String VALUE = "value";
  private static final String TYPE = "type";
  private static final String NAME = "name";

  private Node samlResponseForm;

  private boolean isSamlResponseHidden;
  private boolean isRelayStateHidden;

  @SuppressWarnings("squid:S3398" /* Method in here to simplify builder class */)
  private void parseAndSetFormValues(Node samlResponseForm) {
    this.samlResponseForm = samlResponseForm;

    // Bindings 3.5.4 "If the message is a SAML response, then the form control MUST be named
    // SAMLResponse."
    Node samlResponseNode =
        samlResponseForm
            .children()
            .list()
            .stream()
            .filter(node -> SAML_RESPONSE.equals(node.attributes().get(NAME)))
            .findFirst()
            .orElse(null);

    // Bindings 3.5.4 "If a “RelayState” value is to accompany the SAML protocol message, it MUST be
    // placed in an additional **hidden** form control named RelayState within the same form with
    // the SAML message"

    Node relayStateNode =
        samlResponseForm
            .children()
            .list()
            .stream()
            .filter(node -> RELAY_STATE.equals(node.attributes().get(NAME)))
            .findFirst()
            .orElse(null);

    /*
     * Bindings 3.5.4 "A SAML protocol message is form-encoded by... placing the result **in** a
     * **hidden** form control within a form as defined by [HTML401] Section 17"
     *
     * The two key words here are "in" and "hidden"
     *
     * Assuming "in" in the above quote means in either the value attribute or in the value
     * itself.
     *
     * And "hidden" means both the SAMLResponse and RelayState MUST be placed in "hidden" form controls
     */
    // SAMLResponse portion
    if (samlResponseNode != null) {

      if (isNotEmpty(samlResponseNode.value())) {
        samlResponse = samlResponseNode.value();
      } else if (isNotEmpty(samlResponseNode.attributes().get(VALUE))) {
        samlResponse = samlResponseNode.attributes().get(VALUE);
      }

      if (isNotEmpty(samlResponseNode.getAttribute(TYPE))) {
        isSamlResponseHidden = samlResponseNode.getAttribute(TYPE).equals("hidden");
      }
    }

    // RelayState portion
    if (relayStateNode != null) {

      if (isNotEmpty(relayStateNode.value())) {
        relayState = relayStateNode.value();
      } else if (isNotEmpty(relayStateNode.attributes().get(VALUE))) {
        relayState = relayStateNode.attributes().get(VALUE);
      }

      if (isNotEmpty(relayStateNode.getAttribute(TYPE))) {
        isRelayStateHidden = relayStateNode.getAttribute(TYPE).equals("hidden");
      }
    }
  }

  public Node getSamlResponseForm() {
    return samlResponseForm;
  }

  public boolean isSamlResponseHidden() {
    return isSamlResponseHidden;
  }

  public boolean isRelayStateHidden() {
    return isRelayStateHidden;
  }
}
