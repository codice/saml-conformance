/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.saml.plugin;

public abstract class IdpResponse {
  protected IdpResponse() {}

  // Copy constructor
  protected IdpResponse(IdpResponse response) {
    httpStatusCode = response.httpStatusCode;
    samlResponse = response.samlResponse;
    relayState = response.relayState;
  }

  protected int httpStatusCode;
  protected String samlResponse;
  protected String relayState;

  public int getHttpStatusCode() {
    return httpStatusCode;
  }

  public String getSamlResponse() {
    return samlResponse;
  }

  public String getRelayState() {
    return relayState;
  }
}
