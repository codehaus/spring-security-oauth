package org.springframework.security.oauth.consumer.nonce;

import java.util.UUID;

/**
 * Nonce factory that uses a UUID to generate the nonce.
 *
 * @author Ryan Heaton
 */
public class UUIDNonceFactory implements NonceFactory {

  public String generateNonce() {
    return UUID.randomUUID().toString();
  }
}
