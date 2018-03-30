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
   * Pluggable portion of the test.
   *
   * @param originalResponse - the original {@code RestAssured} response from the initial REDIRECT
   *     authn request
   * @return The response as an {@code IdpRedirectResponse}. The internal builder should be called
   *     to build the response object:
   *     <pre>{@code
   * return new IdpRedirectResponse.Builder()
   * .httpStatusCode(exampleStatusCode)
   * .url(exampleUrl)
   * .build();
   * }
   * where {@code exampleStatusCode} is the http status code returned by the IdP
   * where {@code exampleUrl} is the url in the "Location" header returned by the IdP
   * </pre>
   */
  IdpRedirectResponse getIdpRedirectResponse(Response originalResponse);

  /**
   * Pluggable portion of the test.
   *
   * @param originalResponse - the original {@code RestAssured} response from the initial POST authn
   *     request
   * @return The response as an {@code IdpPostResponse}. The internal builder should be called to
   *     build the response object:
   *     <pre>{@code
   * return new IdpPostResponse.Builder()
   * .httpStatusCode(exampleStatusCode)
   * .samlForm(exampleSampleForm)
   * .build();
   * }
   * where {@code exampleStatusCode} is the http status code returned by the IdP
   * where {@code exampleSamleForm} is the wrapping form containing the samlResponse form control returned by the IdP
   * </pre>
   */
  IdpPostResponse getIdpPostResponse(Response originalResponse);
}
