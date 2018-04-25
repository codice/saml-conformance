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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.cxf.rs.security.saml.sso.SSOConstants;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.saml.WSSSAMLKeyInfoProcessor;
import org.apache.wss4j.dom.validate.Credential;
import org.apache.wss4j.dom.validate.SignatureTrustValidator;
import org.apache.wss4j.dom.validate.Validator;
import org.opensaml.saml.common.SAMLObjectContentReference;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.xmlsec.signature.support.provider.ApacheSantuarioSignatureValidationProviderImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SimpleSign {

  private static final Logger LOGGER = LoggerFactory.getLogger(SimpleSign.class);

  private final SystemCrypto crypto;

  private static final Map<String, String> URI_ALG_MAP = new HashMap<>();

  static {
    URI_ALG_MAP.put("http://www.w3.org/2000/09/xmldsig#dsa-sha1", "SHA1withDSA");
    URI_ALG_MAP.put("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "SHA1withRSA");
  }

  public SimpleSign() throws IOException {
    crypto = new SystemCrypto();
  }

  /** Signing * */

  /**
   * Signs uri value. According to the SAML Spec,
   *
   * <p>"To construct the signature, a string consisting of the concatenation of the RelayState (if
   * present), SigAlg, and SAMLRequest (or SAMLResponse) query string parameters (each one
   * URLencoded) is constructed in one of the following ways (ordered as below):
   * SAMLRequest=value&RelayState=value&SigAlg=value
   * SAMLResponse=value&RelayState=value&SigAlg=value"
   *
   * @param samlType - SAMLRequest or SAMLResponse
   * @param samlRequestOrResponse - request or response already encoded
   * @param relayState - uri encoded relayState (optional) - null is no relay state exists
   */
  public Map<String, String> signUriString(
      String samlType, String samlRequestOrResponse, String relayState) throws SignatureException {
    try {
      X509Certificate[] certificates = getSignatureCertificates();
      String sigAlgo = getSignatureAlgorithm(certificates[0]);
      PrivateKey privateKey = getSignaturePrivateKey();
      java.security.Signature signature = getSignature(certificates[0], privateKey);

      // Construct query parameters
      StringBuilder requestToSign =
          new StringBuilder(samlType).append("=").append(samlRequestOrResponse);
      if (relayState != null) {
        requestToSign
            .append(String.format("&%s=", SSOConstants.RELAY_STATE))
            .append(URLEncoder.encode(relayState, StandardCharsets.UTF_8.name()));
      }
      requestToSign
          .append(String.format("&%s=", SSOConstants.SIG_ALG))
          .append(URLEncoder.encode(sigAlgo, StandardCharsets.UTF_8.name()));

      // Sign uri
      signature.update(requestToSign.toString().getBytes(StandardCharsets.UTF_8.name()));
      byte[] signatureBytes = signature.sign();

      Map<String, String> queryParams = new HashMap<>();
      queryParams.put(samlType, samlRequestOrResponse);
      if (relayState != null) {
        queryParams.put(
            SSOConstants.RELAY_STATE, URLEncoder.encode(relayState, StandardCharsets.UTF_8.name()));
      }
      queryParams.put(
          SSOConstants.SIG_ALG, URLEncoder.encode(sigAlgo, StandardCharsets.UTF_8.name()));
      queryParams.put(
          SSOConstants.SIGNATURE,
          URLEncoder.encode(
              Base64.getEncoder().encodeToString(signatureBytes), StandardCharsets.UTF_8.name()));
      return queryParams;
    } catch (java.security.SignatureException | UnsupportedEncodingException e) {
      throw new SignatureException(e);
    }
  }

  /** Used to sign post requests */
  public void signSamlObject(SignableSAMLObject samlObject) throws SignatureException {
    X509Certificate[] certificates = getSignatureCertificates();
    String sigAlgo = getSignatureAlgorithm(certificates[0]);
    signSamlObject(
        samlObject,
        sigAlgo,
        SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS,
        SignatureConstants.ALGO_ID_DIGEST_SHA1);
  }

  private void signSamlObject(
      SignableSAMLObject samlObject, String sigAlgo, String canonAlgo, String digestAlgo)
      throws SignatureException {
    X509Certificate[] certificates = getSignatureCertificates();
    PrivateKey privateKey = getSignaturePrivateKey();

    // Create the signature
    Signature signature = OpenSAMLUtil.buildSignature();
    if (signature == null) {
      throw new SignatureException("Unable to build signature.");
    }

    signature.setCanonicalizationAlgorithm(canonAlgo);
    signature.setSignatureAlgorithm(sigAlgo);

    BasicX509Credential signingCredential = new BasicX509Credential(certificates[0]);
    signingCredential.setPrivateKey(privateKey);

    signature.setSigningCredential(signingCredential);

    X509KeyInfoGeneratorFactory x509KeyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
    x509KeyInfoGeneratorFactory.setEmitEntityCertificate(true);

    try {
      KeyInfo keyInfo = x509KeyInfoGeneratorFactory.newInstance().generate(signingCredential);
      signature.setKeyInfo(keyInfo);
    } catch (org.opensaml.security.SecurityException e) {
      throw new SignatureException("Error generating KeyInfo from signing credential", e);
    }

    if (samlObject instanceof Response) {
      List<Assertion> assertions = ((Response) samlObject).getAssertions();
      for (Assertion assertion : assertions) {
        assertion.getSignature().setSigningCredential(signingCredential);
      }
    }

    samlObject.setSignature(signature);

    SAMLObjectContentReference contentRef =
        (SAMLObjectContentReference) signature.getContentReferences().get(0);
    contentRef.setDigestAlgorithm(digestAlgo);

    samlObject.releaseDOM();
    samlObject.releaseChildrenDOM(true);
  }

  /** Validating */
  public boolean validateSignature(
      String samlType,
      String encodedRequestOrResponse,
      String relayState,
      String encodedSignature,
      String encodedSigAlg,
      String certificateString)
      throws SignatureException {

    if (encodedSigAlg == null) {
      throw new SignatureException(SignatureException.SigErrorCode.SIG_ALG_NOT_PROVIDED);
    }

    if (encodedSignature == null) {
      throw new SignatureException(SignatureException.SigErrorCode.SIGNATURE_NOT_PROVIDED);
    }

    try {
      StringBuilder queryParams =
          new StringBuilder(samlType).append("=").append(encodedRequestOrResponse);
      if (relayState != null) {
        queryParams.append(String.format("&%s=", SSOConstants.RELAY_STATE)).append(relayState);
      }
      queryParams.append(String.format("&%s=", SSOConstants.SIG_ALG)).append(encodedSigAlg);
      certificateString =
          String.format(
              "%s%n%s%n%s",
              "-----BEGIN CERTIFICATE-----", certificateString, "-----END CERTIFICATE-----");
      String sigAlg = URLDecoder.decode(encodedSigAlg, StandardCharsets.UTF_8.name());
      String signature = URLDecoder.decode(encodedSignature, StandardCharsets.UTF_8.name());

      CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
      Certificate certificate;
      certificate = getCertificate(certificateString, certificateFactory);

      String jceSigAlg = URI_ALG_MAP.get(sigAlg);

      if (jceSigAlg == null) {
        throw new SignatureException(SignatureException.SigErrorCode.INVALID_URI);
      }

      java.security.Signature sig = java.security.Signature.getInstance(jceSigAlg);
      sig.initVerify(certificate.getPublicKey());
      sig.update(queryParams.toString().getBytes(StandardCharsets.UTF_8.name()));

      byte[] decodedSignature = Base64.getDecoder().decode(signature);
      if (new String(decodedSignature, StandardCharsets.UTF_8.name())
          .matches("[ \\t\\n\\x0B\\f\\r]+")) {
        throw new SignatureException(SignatureException.SigErrorCode.LINEFEED_OR_WHITESPACE);
      }

      return sig.verify(decodedSignature);
    } catch (NoSuchAlgorithmException
        | InvalidKeyException
        | CertificateException
        | UnsupportedEncodingException
        | java.security.SignatureException
        | IllegalArgumentException e) {
      throw new SignatureException(e);
    }
  }

  public void validateSignature(Signature signature) throws SignatureException {
    RequestData requestData = new RequestData();
    requestData.setSigVerCrypto(crypto.getSignatureCrypto());
    WSSConfig wssConfig = WSSConfig.getNewInstance();
    requestData.setWssConfig(wssConfig);

    SAMLKeyInfo samlKeyInfo = null;

    KeyInfo keyInfo = signature.getKeyInfo();
    if (keyInfo != null) {
      try {
        samlKeyInfo =
            SAMLUtil.getCredentialFromKeyInfo(
                keyInfo.getDOM(),
                new WSSSAMLKeyInfoProcessor(requestData),
                crypto.getSignatureCrypto());
      } catch (WSSecurityException e) {
        throw new SignatureException("Unable to get KeyInfo.", e);
      }
    }
    if (samlKeyInfo == null) {
      throw new SignatureException("No KeyInfo supplied in the signature");
    }

    validateSignatureAndSamlKey(signature, samlKeyInfo);

    Credential trustCredential = new Credential();
    trustCredential.setPublicKey(samlKeyInfo.getPublicKey());
    trustCredential.setCertificates(samlKeyInfo.getCerts());
    Validator signatureValidator = new SignatureTrustValidator();

    try {
      signatureValidator.validate(trustCredential, requestData);
    } catch (WSSecurityException e) {
      throw new SignatureException("Error validating signature", e);
    }
  }

  private void validateSignatureAndSamlKey(Signature signature, SAMLKeyInfo samlKeyInfo)
      throws SignatureException {
    SAMLSignatureProfileValidator validator = new SAMLSignatureProfileValidator();
    try {
      validator.validate(signature);
    } catch (org.opensaml.xmlsec.signature.support.SignatureException e) {
      throw new SignatureException("Error validating the SAMLKey signature", e);
    }

    BasicX509Credential credential = null;
    if (samlKeyInfo.getCerts() != null) {
      credential = new BasicX509Credential(samlKeyInfo.getCerts()[0]);
    } else {
      throw new SignatureException("Can't get X509Certificate or PublicKey to verify signature.");
    }

    ClassLoader threadLoader = null;
    try {
      threadLoader = Thread.currentThread().getContextClassLoader();
      Thread.currentThread()
          .setContextClassLoader(
              ApacheSantuarioSignatureValidationProviderImpl.class.getClassLoader());
      SignatureValidator.validate(signature, credential);
    } catch (org.opensaml.xmlsec.signature.support.SignatureException e) {
      throw new SignatureException("Error validating the XML signature", e);
    } finally {
      if (threadLoader != null) {
        Thread.currentThread().setContextClassLoader(threadLoader);
      }
    }
  }

  /** Private Getters */
  private java.security.Signature getSignature(X509Certificate certificate, PrivateKey privateKey)
      throws SignatureException {
    String jceSigAlgo = "SHA1withRSA";
    if ("DSA".equalsIgnoreCase(certificate.getPublicKey().getAlgorithm())) {
      jceSigAlgo = "SHA1withDSA";
    }

    java.security.Signature signature;
    try {
      signature = java.security.Signature.getInstance(jceSigAlgo);
    } catch (NoSuchAlgorithmException e) {
      throw new SignatureException(e);
    }
    try {
      signature.initSign(privateKey);
    } catch (InvalidKeyException e) {
      throw new SignatureException(e);
    }
    return signature;
  }

  private String getSignatureAlgorithm(X509Certificate certificate) {
    String sigAlgo = SSOConstants.RSA_SHA1;
    String pubKeyAlgo = certificate.getPublicKey().getAlgorithm();

    if (pubKeyAlgo.equalsIgnoreCase("DSA")) {
      sigAlgo = SSOConstants.DSA_SHA1;
    }

    LOGGER.debug("Using Signature algorithm {}", sigAlgo);

    return sigAlgo;
  }

  private X509Certificate[] getSignatureCertificates() throws SignatureException {
    CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ALIAS);
    cryptoType.setAlias(crypto.getSignatureAlias());
    X509Certificate[] issuerCerts;

    try {
      issuerCerts = crypto.getSignatureCrypto().getX509Certificates(cryptoType);
    } catch (WSSecurityException e) {
      throw new SignatureException(e);
    }

    if (issuerCerts == null) {
      throw new SignatureException(
          "No certs were found to sign the request using name: " + crypto.getSignatureAlias());
    }

    return issuerCerts;
  }

  private PrivateKey getSignaturePrivateKey() throws SignatureException {
    PrivateKey privateKey;
    try {
      privateKey =
          crypto
              .getSignatureCrypto()
              .getPrivateKey(crypto.getSignatureAlias(), crypto.getSignaturePassword());
    } catch (WSSecurityException e) {
      throw new SignatureException(e);
    }
    return privateKey;
  }

  private Certificate getCertificate(
      String certificateString, CertificateFactory certificateFactory)
      throws UnsupportedEncodingException, SignatureException {
    Certificate certificate;
    try {
      certificate =
          certificateFactory.generateCertificate(
              new ByteArrayInputStream(certificateString.getBytes(StandardCharsets.UTF_8.name())));
    } catch (CertificateException e) {
      throw new SignatureException(SignatureException.SigErrorCode.INVALID_CERTIFICATE);
    }
    return certificate;
  }

  @SuppressWarnings("squid:S1165" /* errorCode mutable for legacy compatibility */)
  public static class SignatureException extends Exception {

    public enum SigErrorCode {
      INVALID_CERTIFICATE,
      SIG_ALG_NOT_PROVIDED,
      SIGNATURE_NOT_PROVIDED,
      INVALID_URI,
      LINEFEED_OR_WHITESPACE
    }

    private SigErrorCode sigErrorCode;

    public SignatureException() {}

    public SignatureException(Throwable cause) {
      super(cause);
    }

    public SignatureException(String message) {
      super(message);
    }

    public SignatureException(String message, Throwable cause) {
      super(message, cause);
    }

    public SignatureException(SigErrorCode sigErrorCode) {
      super();
      setErrorCode(sigErrorCode);
    }

    public SigErrorCode getErrorCode() {
      return sigErrorCode;
    }

    public void setErrorCode(SigErrorCode sigErrorCode) {
      this.sigErrorCode = sigErrorCode;
    }
  }
}
