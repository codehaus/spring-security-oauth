package org.springframework.security.oauth.provider.nonce;

import org.springframework.security.oauth.common.OAuthException;

/**
 * @author Ryan Heaton
 */
public class NonceAlreadyUsedException extends OAuthException {
  public NonceAlreadyUsedException(String msg) {
    super(msg);
  }
}
