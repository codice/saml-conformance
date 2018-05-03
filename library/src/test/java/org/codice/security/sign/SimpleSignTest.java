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
package org.codice.security.sign;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collection;
import java.util.Map;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.rs.security.saml.sso.SSOConstants;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.util.DOM2Writer;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

@RunWith(Parameterized.class)
public class SimpleSignTest {
  private static final String RSA = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  private static final String DSA = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
  private static final String TEST_RELAY = "relaystate";
  private static final String RSA_CERT_STRING =
      "MIICsDCCAhmgAwIBAgIGAWH8X/0MMA0GCSqGSIb3DQEBCwUAMIGEMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQVoxDDAKBgNVBAoTA0RERjEMMAoGA1UECxMDRGV2MRkwFwYDVQQDExBEREYgRGVtbyBSb290IENBMTEwLwYJKoZIhvcNAQkBFiJlbWFpbEFkZHJlc3M9ZGRmcm9vdGNhQGV4YW1wbGUub3JnMCAXDTE4MDMwNTE3MzMyNFoYDzIxMTgwMzA1MTczMzI0WjATMREwDwYDVQQDDAhzYW1saG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKvxMUgWYH/1BBbS6gAV8zmMgqrhlnNvbn8nFyHewcNC4lkYmh3TUXbxxymfvCduOSDKZh3DJN65oL1PKc8gozZOR978VaxizPCjJNUTCzXQ4pfyHE0GIOkynZT63ZoJhlbJaD7sosbcXdD18CZZ/c3lS+4W2XeMClQoHNgmho14i9I/tf2DJ5j/dIrOk5UJ4mg9xTA3TFnLPLpPiMtvW/QQmfK1z59LBIFnGr9OchiWyJPxe8ND0LEsDv0NQ0CP+LhdM3wNuZnxjV5IdPXp1GKF24ouBUa3kGtYrdu+nj2icpp/tVjOGFnBuswH7rckKEzcmYAdW1buG00AmydLrg8CAwEAAaMXMBUwEwYDVR0RBAwwCoIIc2FtbGhvc3QwDQYJKoZIhvcNAQELBQADgYEAoPIq6VIT/pR0VF2bejTog3JEM4y01qI30CXjP58PVHjPJcQxDSQCQc/GFPWfFNaSwg9LR0nPXbhRPnwpveROEzYXabV60e+8Ny9VsGu7Siu7cdcuM5ZpTdSamtioHZ1LDw4lvtLgXTiYmipm55SY9DIhxVgULylq1tOSblgS66M=";
  private static final String DSA_CERT_STRING =
      "MIID6zCCA1SgAwIBAgIJAJmIBWkIlXcRMA0GCSqGSIb3DQEBBQUAMIGEMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQVoxDDAKBgNVBAoTA0RERjEMMAoGA1UECxMDRGV2MRkwFwYDVQQDExBEREYgRGVtbyBSb290IENBMTEwLwYJKoZIhvcNAQkBFiJlbWFpbEFkZHJlc3M9ZGRmcm9vdGNhQGV4YW1wbGUub3JnMB4XDTE4MDUwOTE1NDUyOFoXDTE5MDUwOTE1NDUyOFowTDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkFaMQwwCgYDVQQKDANEREYxDDAKBgNVBAsMA0RldjEUMBIGA1UEAwwLc2FtbGhvc3Rkc2EwggG4MIIBLAYHKoZIzjgEATCCAR8CgYEAvSzXEhq+o1re6lKMzgYepZ2+18xiZChKAyhfSIzpAUXR8kmYKIEz/tIW+rXv+t7CSGoiKgIj8lHoEwLQ4wnaOg9u51PE5xV9f0ig9vCQGzwXq8yi3YBKfWDCSWXN0cEsBP6Xfvf3boFbWjzMvwuE2VfkAmQzOhL3372mGtuMBZ8CFQDa0xC8ejL6JCRpt1JVU2DVY9/fdwKBgQCgMcRXMpRlw01I4V2DbaynZPID1H2FdPOnPFqhVgXK13fJe0i0oa3hNZII7UrdCMI7MZ3eMShXbKDWdb0RnAPXleVdnWsTWZU4puozmuBI0AH7BUfN7tQPFVmwqPXpL4DJoKH2p3dcsUnVAKHa+SehGnVA0ZiHPnK7sdrb6Ns52gOBhQACgYEApH128rhv7r3q8G1eCSYRS8bEO2Rel9FV74igdcfpvD5FqjOhQ1K5zxKVnqQbqqaNTuRlhWb9C94LJB/KozNXWf8TCP/gbz6pd0nJGLP84lpke/ffblbCS05XtNtg4X1qOu+HdNO9xedEoM0K0QlyF09LCZNunr4CTj5z8uPDICCjgYEwfzAJBgNVHRMEAjAAMCcGCWCGSAGG+EIBDQQaFhhGT1IgVEVTVElORyBQVVJQT1NFIE9OTFkwHQYDVR0OBBYEFJgSNpRmsXQSHbIXORCCPipDHKFGMB8GA1UdIwQYMBaAFOFUx5ffCsK/qV94XjsLK+RIF73GMAkGA1UdEQQCMAAwDQYJKoZIhvcNAQEFBQADgYEAQW4bQOzumWE3erDYDy11O3wbk2zL2TN72DdDn5p58QTA3cDhlOBCdyeCBtRJ0RbSDWEswjwMiXuypYzvNLZ4z7QqlsvoCfE7SI6jBNkAhqP04EuEjPBx8NZUQsYp4tTeJDPGHcY7xdl1SqfGcQ1ofSGGl/EzoSmHQxH01yhpYhU=";
  private static final String TEST_ENTITY_ID = "https://samlhostdsa:8993/services/saml";

  private SimpleSign simpleSign;
  private String expectedSigAlg;
  private String expectedSigAlgEncoded;
  private String certString;
  private String exampleSamlRequest;
  private AuthnRequest exampleAuthnRequest;

  @Parameterized.Parameters
  public static Collection<Object[]> simpleSignVariations() throws IOException, URISyntaxException {
    return Arrays.asList(
        new Object[][] {
          {new SimpleSign(), RSA, RSA_CERT_STRING},
          {new SimpleSign(TEST_ENTITY_ID), DSA, DSA_CERT_STRING}
        });
  }

  public SimpleSignTest(SimpleSign simpleSign, String expectedSigAlg, String certString)
      throws Exception {
    OpenSAMLUtil.initSamlEngine();

    this.simpleSign = simpleSign;
    this.expectedSigAlg = expectedSigAlg;
    this.expectedSigAlgEncoded = URLEncoder.encode(expectedSigAlg, StandardCharsets.UTF_8.name());
    this.certString = certString;

    exampleAuthnRequest = new AuthnRequestBuilder().buildObject();
    exampleSamlRequest = Encoder.encodeRedirectMessage(authnRequestToString(exampleAuthnRequest));
  }

  @Test
  public void signUriStringWithoutRelayStateReturns3QueryParameters() throws Exception {
    Map<String, String> output =
        simpleSign.signUriString(SSOConstants.SAML_REQUEST, exampleSamlRequest, null);

    assertThat(output.get(SSOConstants.SIG_ALG), is(expectedSigAlgEncoded));
    assertThat(output.get(SSOConstants.SAML_REQUEST), is(exampleSamlRequest));
    assertThat(output.get(SSOConstants.SIGNATURE), is(notNullValue()));
    assertThat(output.size(), is(3));
  }

  @Test
  public void signUriStringWithRelayStateReturns4QueryParameters() throws Exception {
    Map<String, String> output =
        simpleSign.signUriString(SSOConstants.SAML_REQUEST, exampleSamlRequest, TEST_RELAY);

    assertThat(output.get(SSOConstants.SIG_ALG), is(expectedSigAlgEncoded));
    assertThat(output.get(SSOConstants.SAML_REQUEST), is(exampleSamlRequest));
    assertThat(output.get(SSOConstants.SIGNATURE), is(notNullValue()));
    assertThat(output.get(SSOConstants.RELAY_STATE), is(TEST_RELAY));
    assertThat(output.size(), is(4));
  }

  @Test
  public void signUriStringWithoutRelayStateReturnsValidSignature() throws Exception {
    Map<String, String> output =
        simpleSign.signUriString(SSOConstants.SAML_REQUEST, exampleSamlRequest, null);

    boolean isValidSignature =
        simpleSign.validateSignature(
            SSOConstants.SAML_REQUEST,
            output.get(SSOConstants.SAML_REQUEST),
            null,
            output.get(SSOConstants.SIGNATURE),
            output.get(SSOConstants.SIG_ALG),
            certString);
    assertThat(isValidSignature, is(true));
  }

  @Test
  public void signSamlObjectAddsSignatureElementWithCorrectAlgorithm() throws Exception {
    assertThat(exampleAuthnRequest.getSignature(), is(nullValue()));

    simpleSign.signSamlObject(exampleAuthnRequest);

    assertThat(exampleAuthnRequest.getSignature(), is(notNullValue()));
    assertThat(exampleAuthnRequest.getSignature().getSignatureAlgorithm(), is(expectedSigAlg));
  }

  private String authnRequestToString(AuthnRequest authnRequest) throws Exception {
    Document doc = DOMUtils.createDocument();
    doc.appendChild(doc.createElement("root"));

    Node requestElement = OpenSAMLUtil.toDom(authnRequest, doc);
    return DOM2Writer.nodeToString(requestElement);
  }
}
