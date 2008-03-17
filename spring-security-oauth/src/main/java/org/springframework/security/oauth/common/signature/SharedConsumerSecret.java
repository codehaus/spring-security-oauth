package org.springframework.security.oauth.common.signature;

/**
 * A signature secret that consists of a consumer secret and a tokent secret.
 *
 * @author Ryan Heaton
 */
public class SharedConsumerSecret implements SignatureSecret {

  private final String consumerSecret;

  public SharedConsumerSecret(String consumerSecret) {
    this.consumerSecret = consumerSecret;
  }

  /**
   * The consumer secret.
   *
   * @return The consumer secret.
   */
  public String getConsumerSecret() {
    return consumerSecret;
  }

}
