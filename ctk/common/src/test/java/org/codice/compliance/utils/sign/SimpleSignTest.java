/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.utils.sign;

import static org.codice.compliance.utils.TestCommon.currentSPIssuer;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.notNullValue;
import static org.hamcrest.Matchers.nullValue;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.apache.cxf.helpers.DOMUtils;
import org.apache.cxf.rs.security.saml.sso.SSOConstants;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.util.DOM2Writer;
import org.codice.security.sign.Encoder;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;
import org.w3c.dom.Document;
import org.w3c.dom.Node;

public class SimpleSignTest {
  private static final String RSA = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
  private static final String DSA = "http://www.w3.org/2000/09/xmldsig#dsa-sha1";
  private static final String TEST_RELAY = "relaystate";
  private static final String RSA_CERT_STRING =
      "MIICsDCCAhmgAwIBAgIGAWH8X/0MMA0GCSqGSIb3DQEBCwUAMIGEMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQVoxDDAKBgNVBAoTA0RERjEMMAoGA1UECxMDRGV2MRkwFwYDVQQDExBEREYgRGVtbyBSb290IENBMTEwLwYJKoZIhvcNAQkBFiJlbWFpbEFkZHJlc3M9ZGRmcm9vdGNhQGV4YW1wbGUub3JnMCAXDTE4MDMwNTE3MzMyNFoYDzIxMTgwMzA1MTczMzI0WjATMREwDwYDVQQDDAhzYW1saG9zdDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKvxMUgWYH/1BBbS6gAV8zmMgqrhlnNvbn8nFyHewcNC4lkYmh3TUXbxxymfvCduOSDKZh3DJN65oL1PKc8gozZOR978VaxizPCjJNUTCzXQ4pfyHE0GIOkynZT63ZoJhlbJaD7sosbcXdD18CZZ/c3lS+4W2XeMClQoHNgmho14i9I/tf2DJ5j/dIrOk5UJ4mg9xTA3TFnLPLpPiMtvW/QQmfK1z59LBIFnGr9OchiWyJPxe8ND0LEsDv0NQ0CP+LhdM3wNuZnxjV5IdPXp1GKF24ouBUa3kGtYrdu+nj2icpp/tVjOGFnBuswH7rckKEzcmYAdW1buG00AmydLrg8CAwEAAaMXMBUwEwYDVR0RBAwwCoIIc2FtbGhvc3QwDQYJKoZIhvcNAQELBQADgYEAoPIq6VIT/pR0VF2bejTog3JEM4y01qI30CXjP58PVHjPJcQxDSQCQc/GFPWfFNaSwg9LR0nPXbhRPnwpveROEzYXabV60e+8Ny9VsGu7Siu7cdcuM5ZpTdSamtioHZ1LDw4lvtLgXTiYmipm55SY9DIhxVgULylq1tOSblgS66M=";
  private static final String DSA_CERT_STRING =
      "MIID6zCCA1SgAwIBAgIJAJmIBWkIlXcRMA0GCSqGSIb3DQEBBQUAMIGEMQswCQYDVQQGEwJVUzELMAkGA1UECBMCQVoxDDAKBgNVBAoTA0RERjEMMAoGA1UECxMDRGV2MRkwFwYDVQQDExBEREYgRGVtbyBSb290IENBMTEwLwYJKoZIhvcNAQkBFiJlbWFpbEFkZHJlc3M9ZGRmcm9vdGNhQGV4YW1wbGUub3JnMB4XDTE4MDUwOTE1NDUyOFoXDTE5MDUwOTE1NDUyOFowTDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkFaMQwwCgYDVQQKDANEREYxDDAKBgNVBAsMA0RldjEUMBIGA1UEAwwLc2FtbGhvc3Rkc2EwggG4MIIBLAYHKoZIzjgEATCCAR8CgYEAvSzXEhq+o1re6lKMzgYepZ2+18xiZChKAyhfSIzpAUXR8kmYKIEz/tIW+rXv+t7CSGoiKgIj8lHoEwLQ4wnaOg9u51PE5xV9f0ig9vCQGzwXq8yi3YBKfWDCSWXN0cEsBP6Xfvf3boFbWjzMvwuE2VfkAmQzOhL3372mGtuMBZ8CFQDa0xC8ejL6JCRpt1JVU2DVY9/fdwKBgQCgMcRXMpRlw01I4V2DbaynZPID1H2FdPOnPFqhVgXK13fJe0i0oa3hNZII7UrdCMI7MZ3eMShXbKDWdb0RnAPXleVdnWsTWZU4puozmuBI0AH7BUfN7tQPFVmwqPXpL4DJoKH2p3dcsUnVAKHa+SehGnVA0ZiHPnK7sdrb6Ns52gOBhQACgYEApH128rhv7r3q8G1eCSYRS8bEO2Rel9FV74igdcfpvD5FqjOhQ1K5zxKVnqQbqqaNTuRlhWb9C94LJB/KozNXWf8TCP/gbz6pd0nJGLP84lpke/ffblbCS05XtNtg4X1qOu+HdNO9xedEoM0K0QlyF09LCZNunr4CTj5z8uPDICCjgYEwfzAJBgNVHRMEAjAAMCcGCWCGSAGG+EIBDQQaFhhGT1IgVEVTVElORyBQVVJQT1NFIE9OTFkwHQYDVR0OBBYEFJgSNpRmsXQSHbIXORCCPipDHKFGMB8GA1UdIwQYMBaAFOFUx5ffCsK/qV94XjsLK+RIF73GMAkGA1UdEQQCMAAwDQYJKoZIhvcNAQEFBQADgYEAQW4bQOzumWE3erDYDy11O3wbk2zL2TN72DdDn5p58QTA3cDhlOBCdyeCBtRJ0RbSDWEswjwMiXuypYzvNLZ4z7QqlsvoCfE7SI6jBNkAhqP04EuEjPBx8NZUQsYp4tTeJDPGHcY7xdl1SqfGcQ1ofSGGl/EzoSmHQxH01yhpYhU=";
  private static final String SP_ISSUER = "https://samlhost:8993/services/saml";
  private static final String DSA_SP_ISSUER = "https://samlhostdsa:8993/services/saml";

  private SimpleSign simpleSign;
  private String expectedSigAlg;
  private String expectedSigAlgEncoded;
  private String certString;
  private String exampleSamlRequest;
  private AuthnRequest exampleAuthnRequest;

  private static final SignInfo[] SIGN_INFOS = {
    new SignInfo(SP_ISSUER, RSA, RSA_CERT_STRING), new SignInfo(DSA_SP_ISSUER, DSA, DSA_CERT_STRING)
  };

  static SignInfo[] signInfos() {
    return SIGN_INFOS;
  }

  static class SignInfo {
    private String issuer;
    private String sigAlg;
    private String cert;

    SignInfo(String issuer, String sigAlg, String cert) {
      this.issuer = issuer;
      this.sigAlg = sigAlg;
      this.cert = cert;
    }
  }

  public SimpleSignTest() {
    OpenSAMLUtil.initSamlEngine();
  }

  private void setupParams(SignInfo signInfo) throws Exception {
    // Set parameter-dependent variables
    currentSPIssuer = signInfo.issuer;
    this.expectedSigAlg = signInfo.sigAlg;
    this.expectedSigAlgEncoded = URLEncoder.encode(expectedSigAlg, StandardCharsets.UTF_8.name());
    this.certString = signInfo.cert;

    // Set universal variables
    this.simpleSign = new SimpleSign();
    exampleAuthnRequest = new AuthnRequestBuilder().buildObject();
    exampleSamlRequest = Encoder.encodeRedirectMessage(authnRequestToString(exampleAuthnRequest));
  }

  @ParameterizedTest
  @MethodSource("signInfos")
  public void signUriStringWithoutRelayStateReturns3QueryParameters(SignInfo signInfo)
      throws Exception {
    setupParams(signInfo);
    Map<String, String> output =
        simpleSign.signUriString(SSOConstants.SAML_REQUEST, exampleSamlRequest, null);

    assertThat(output.get(SSOConstants.SIG_ALG), is(expectedSigAlgEncoded));
    assertThat(output.get(SSOConstants.SAML_REQUEST), is(exampleSamlRequest));
    assertThat(output.get(SSOConstants.SIGNATURE), is(notNullValue()));
    assertThat(output.size(), is(3));
  }

  @ParameterizedTest
  @MethodSource("signInfos")
  public void signUriStringWithRelayStateReturns4QueryParameters(SignInfo signInfo)
      throws Exception {
    setupParams(signInfo);
    Map<String, String> output =
        simpleSign.signUriString(SSOConstants.SAML_REQUEST, exampleSamlRequest, TEST_RELAY);

    assertThat(output.get(SSOConstants.SIG_ALG), is(expectedSigAlgEncoded));
    assertThat(output.get(SSOConstants.SAML_REQUEST), is(exampleSamlRequest));
    assertThat(output.get(SSOConstants.SIGNATURE), is(notNullValue()));
    assertThat(output.get(SSOConstants.RELAY_STATE), is(TEST_RELAY));
    assertThat(output.size(), is(4));
  }

  @ParameterizedTest
  @MethodSource("signInfos")
  public void signUriStringWithoutRelayStateReturnsValidSignature(SignInfo signInfo)
      throws Exception {
    setupParams(signInfo);
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

  @ParameterizedTest
  @MethodSource("signInfos")
  public void signSamlObjectAddsSignatureElementWithCorrectAlgorithm(SignInfo signInfo)
      throws Exception {
    setupParams(signInfo);
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
