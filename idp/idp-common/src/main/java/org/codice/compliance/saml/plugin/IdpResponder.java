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

public interface IdpResponder {
  /**
   * Plugable portion of the test.
   *
   * @param originalResponse - the originalResponse from the initial REDIRECT authn request
   * @return A string originalResponse
   */
  String getIdpRedirectResponse(Response originalResponse);

  /**
   * Plugable portion of the test.
   *
   * @param originalResponse - the response from the initial POST authn request
   * @return A string response
   */
  String getIdpPostResponse(Response originalResponse);
}
