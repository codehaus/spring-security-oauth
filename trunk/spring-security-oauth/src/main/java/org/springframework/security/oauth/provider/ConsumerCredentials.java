package org.springframework.security.oauth.provider;

/**
 * The credentials for an OAuth consumer request.
 *
 * @author Ryan Heaton
 */
public class ConsumerCredentials {

  private final String consumerKey;
  private final String signature;
  private final String signatureMethod;
  private final String signatureBaseString;
  private final String token;

  public ConsumerCredentials(String consumerKey, String signature, String signatureMethod, String signatureBaseString, String token) {
    this.signature = signature;
    this.signatureMethod = signatureMethod;
    this.signatureBaseString = signatureBaseString;
    this.consumerKey = consumerKey;
    this.token = token;
  }

  /**
   * The consumer key.
   *
   * @return The consumer key.
   */
  public String getConsumerKey() {
    return consumerKey;
  }

  /**
   * The signature.
   *
   * @return The signature.
   */
  public String getSignature() {
    return signature;
  }

  /**
   * The signature method.
   *
   * @return The signature method.
   */
  public String getSignatureMethod() {
    return signatureMethod;
  }

  /**
   * The signature base string.
   *
   * @return The signature base string.
   */
  public String getSignatureBaseString() {
    return signatureBaseString;
  }

  /**
   * The OAuth token.
   *
   * @return The OAuth token.
   */
  public String getToken() {
    return token;
  }
}
