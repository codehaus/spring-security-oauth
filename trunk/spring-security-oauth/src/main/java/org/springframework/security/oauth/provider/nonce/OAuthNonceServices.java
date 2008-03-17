package org.springframework.security.oauth.provider.nonce;

import org.acegisecurity.AuthenticationException;
import org.springframework.security.oauth.provider.ConsumerDetails;

/**
 * @author Ryan Heaton
 */
public interface OAuthNonceServices {

  /**
   * Validate a nonce for a specific consumer timestamp. This is an opportunity to prevent replay attacks.  Every nonce
   * should be unique for each consumer timestamp. In other words, this method should throw a BadCredentialsException
   * if the specified nonce was used by the consumer more than once with the specified timestamp.
   *
   * @param consumerDetails The consumer details.
   * @param timestamp The timestamp.
   * @param nonce The nonce.
   * @return Whether the timestamp is a new timestamp.  This gives the authentication processor the chance to enforce that all peer requests have the same timestamp, per the OAuth spec.
   * @throws org.acegisecurity.AuthenticationException If the nonce failed to validate.
   */
  boolean validateNonce(ConsumerDetails consumerDetails, long timestamp, String nonce) throws AuthenticationException;
  
}
