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

import com.jayway.restassured.response.Response;

/**
 * This interface provides a mechanism for implementers to handle a portion of the SAML IdP
 * interactions that are not constrained by the SAML specification (and are therefore
 * implementation-dependent).
 */
public interface IdpSSOResponder {

  /**
   * After the tests send an AuthnRequest to the IdP using the Redirect binding, they will hand the
   * HTTP response they get to this method.
   *
   * <p>This method is responsible for handling the implementation-specific interactions that need
   * to occur before successfully authenticating a user and getting the SAML response. Once the SAML
   * response is received, this method should build and return the RestAssured Response object.
   *
   * @param originalResponse - the original {@code RestAssured} response from the initial REDIRECT
   *     authn request
   * @return The {@code RestAssured} response containing the SAML response. </pre>
   *     </pre>
   */
  Response getResponseForRedirectRequest(Response originalResponse);

  /**
   * After the tests send an AuthnRequest to the IdP using the POST binding, they will hand the HTTP
   * response they get to this method.
   *
   * <p>This method is responsible for handling the implementation-specific interactions that need
   * to occur before successfully authenticating a user and getting the SAML response. Once the SAML
   * response is received, this method should build and return the RestAssured Response object.
   *
   * @param originalResponse - the original {@code RestAssured} response from the initial POST authn
   *     request
   * @return The {@code RestAssured} response containing the SAML response. </pre>
   */
  Response getResponseForPostRequest(Response originalResponse);
}
