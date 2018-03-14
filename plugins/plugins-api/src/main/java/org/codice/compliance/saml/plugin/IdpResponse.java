package org.codice.compliance.saml.plugin;

import org.w3c.dom.Node;

public abstract class IdpResponse {
  protected IdpResponse() {}

  protected int httpStatusCode;
  protected String samlResponse;
  protected String relayState;

  // not set by builder
  private boolean isRelayStateGiven;
  private String decodedSamlResponse;
  private Node responseDom;

  public int getHttpStatusCode() {
    return httpStatusCode;
  }

  public String getSamlResponse() {
    return samlResponse;
  }

  public String getRelayState() {
    return relayState;
  }

  public boolean isRelayStateGiven() {
    return isRelayStateGiven;
  }

  public void setRelayStateGiven(boolean relayStateGiven) {
    this.isRelayStateGiven = relayStateGiven;
  }

  public String getDecodedSamlResponse() {
    return decodedSamlResponse;
  }

  public void setDecodedSamlResponse(String decodedSamlResponse) {
    this.decodedSamlResponse = decodedSamlResponse;
  }

  public Node getResponseDom() {
    return responseDom;
  }

  public void setResponseDom(Node responseDom) {
    this.responseDom = responseDom;
  }
}
