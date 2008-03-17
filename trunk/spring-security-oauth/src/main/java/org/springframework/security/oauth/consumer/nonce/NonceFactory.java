package org.springframework.security.oauth.consumer.nonce;

/**
 * A nonce factory.
 *
 * @author Ryan Heaton
 */
public interface NonceFactory {

  /**
   * Generate a nonce.
   *
   * @return The nonce that was generated.
   */
  String generateNonce();
}
