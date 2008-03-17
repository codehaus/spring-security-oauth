package org.springframework.security.oauth.provider.nonce;

import org.acegisecurity.AuthenticationException;
import org.springframework.security.oauth.provider.ConsumerDetails;

/**
 * No-op nonce services. Assumes all nonces are valid. This leaves the provider exposed to the dangers
 * of an unlimited timestamp validity window and OAuth request replay attacks.
 *
 * @author Ryan Heaton
 */
public class NullNonceServices implements OAuthNonceServices {

  public boolean validateNonce(ConsumerDetails consumerDetails, long timestamp, String nonce) throws AuthenticationException {
    return false;
  }
}
