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

import com.google.common.base.Splitter;
import java.util.List;

/**
 * This class is the return type for methods of the {@code IdpResponder} interface on the REDIRECT
 * Binding. Once the user implemented portion finishes its interaction with the IdP under testing,
 * it should return an {@code IdpRedirectResponse}.
 *
 * <p>An {@code IdpRedirectResponse} is created by passing in the resultant RestAssured {@code
 * Response} to its constructor.
 *
 * <p>Example: {@code return IdpRedirectResponse(restAssuredResponse); }
 */
public class IdpRedirectResponse extends IdpResponse {

  // Copy constructor
  protected IdpRedirectResponse(IdpRedirectResponse response) {
    super(response);
    url = response.url;
    path = response.path;
    parameters = response.parameters;
  }

  // TODO remove url field if not used in Binding Verification
  protected String url;
  protected String path;
  protected String parameters;

  /* TODO "Manually change DDF IdP to respond with 302/303 status code for Redirect"
  * When ticket is finished, put in this constructor:
  *
  public IdpRedirectResponse(Response response) {
    httpStatusCode = response.statusCode();
    this.url = response.header("Location");
    List<String> splitUrl = Splitter.on("?").splitToList(url);
    path = splitUrl.get(0);
    parameters = splitUrl.get(1);
  }
  *
  * And delete everything below in this class
  */

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

  private IdpRedirectResponse() {}

  @SuppressWarnings("squid:S3398" /* Method in here to simplify builder class */)
  private void parseAndSetUrlValues(String url) {
    this.url = url;
    List<String> splitUrl = Splitter.on("?").splitToList(url);
    path = splitUrl.get(0);
    parameters = splitUrl.get(1);
  }
}
