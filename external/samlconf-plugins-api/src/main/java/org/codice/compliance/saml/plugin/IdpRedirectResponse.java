/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.saml.plugin;

import com.google.common.base.Splitter;
import java.util.List;

/**
 * This class is the return type for methods of the {@code IdpSSOResponder} interface on the
 * REDIRECT Binding. Once the user implemented portion finishes its interaction with the IdP under
 * testing, it should return an {@code IdpRedirectResponse}.
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

  protected String url;
  protected String path;
  protected String parameters;

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
