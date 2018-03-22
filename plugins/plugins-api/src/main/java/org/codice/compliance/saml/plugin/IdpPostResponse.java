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
 *   <li>IdpPostResponse.Builder.samlForm(Node)
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
 *   return new IdpPostResponse.Builder()
 *       .httpStatusCode(exampleStatusCode)
 *       .samlForm(exampleSamlForm)
 *       .build();
 * </pre>
 *
 * </blockquote>
 */
public class IdpPostResponse extends IdpResponse {

  public static class Builder {

    private IdpPostResponse idpPostResponse = new IdpPostResponse();

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
  protected static final String NAME = "name";

  private IdpPostResponse() {}

  // Copy constructor
  protected IdpPostResponse(IdpPostResponse response) {
    super(response);
    responseForm = response.responseForm;
    samlResponseForm = response.samlResponseForm;
    relayStateForm = response.relayStateForm;
  }

  // TODO remove responseForm field if not used in Binding Verification
  protected Node responseForm;
  protected Node samlResponseForm;
  protected Node relayStateForm;

  /**
   * This method is responsible for
   *
   * @param responseForm is a RestAssured response node that is returned from the user-interactive
   *     plugin portion of the
   */
  @SuppressWarnings("squid:S3398" /* Method in here to simplify builder class */)
  private void parseAndSetFormValues(Node responseForm) {
    this.responseForm = responseForm;

    // Bindings 3.5.4 "If the message is a SAML response, then the form control MUST be named
    // SAMLResponse."
    samlResponseForm =
        responseForm
            .children()
            .list()
            .stream()
            .filter(node -> SAML_RESPONSE.equalsIgnoreCase(node.attributes().get(NAME)))
            .findFirst()
            .orElse(null);

    // Bindings 3.5.4 "If a “RelayState” value is to accompany the SAML protocol message, it MUST be
    // placed in an additional **hidden** form control named RelayState within the same form with
    // the SAML message"

    relayStateForm =
        responseForm
            .children()
            .list()
            .stream()
            .filter(node -> RELAY_STATE.equalsIgnoreCase(node.attributes().get(NAME)))
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
    if (samlResponseForm != null) {
      if (isNotEmpty(samlResponseForm.value())) {
        samlResponse = samlResponseForm.value();
      } else if (isNotEmpty(samlResponseForm.attributes().get(VALUE))) {
        samlResponse = samlResponseForm.attributes().get(VALUE);
      }
    }

    // RelayState portion
    if (relayStateForm != null) {
      if (isNotEmpty(relayStateForm.value())) {
        relayState = relayStateForm.value();
      } else if (isNotEmpty(relayStateForm.attributes().get(VALUE))) {
        relayState = relayStateForm.attributes().get(VALUE);
      }
    }
  }
}
