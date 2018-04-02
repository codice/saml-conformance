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
import com.jayway.restassured.response.Response;

/**
 * This class is the return type for methods of the {@code IdpResponder} interface for the POST
 * Binding. Once the user implemented portion finishes its interaction with the IdP under testing,
 * it should return an {@code IdpPostResponse}.
 *
 * <p>An {@code IdpPostResponse} is created by passing in the resultant RestAssured {@code Response}
 * to its constructor.
 *
 * <p>Example: {@code return IdpPostResponse(restAssuredResponse); }
 */
public class IdpPostResponse extends IdpResponse {

  private static final String VALUE = "value";
  protected static final String NAME = "name";

  public IdpPostResponse(Response response) {
    responseForm =
        response
            .then()
            .extract()
            .htmlPath()
            .getList("**.find { it.name() == 'form' }", Node.class)
            .stream()
            .filter(this::hasSamlResponseFormControl)
            .findFirst()
            .orElse(null);

    if (responseForm != null) {
      parseAndSetFormValues();
    }
  }

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

  private boolean hasSamlResponseFormControl(Node form) {
    return form.children()
        .list()
        .stream()
        .map(formControl -> formControl.getAttribute(NAME))
        .anyMatch(SAML_RESPONSE::equalsIgnoreCase);
  }

  private void parseAndSetFormValues() {
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

    samlResponse = extractValue(samlResponseForm);
    relayState = extractValue(relayStateForm);
  }

  private String extractValue(Node node) {
    if (node == null) {
      return null;
    }

    if (isNotEmpty(node.value())) {
      return node.value();
    }

    if (node.attributes() == null) {
      return null;
    }

    if (isNotEmpty(node.attributes().get(VALUE))) {
      return node.attributes().get(VALUE);
    }

    return null;
  }
}
