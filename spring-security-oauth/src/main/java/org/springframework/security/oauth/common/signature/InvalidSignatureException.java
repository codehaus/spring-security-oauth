package org.springframework.security.oauth.common.signature;

import org.springframework.security.oauth.common.OAuthException;

/**
 * Thrown when a signature is invalid.
 *
 * @author Ryan Heaton
 */
public class InvalidSignatureException extends OAuthException {

  public InvalidSignatureException(String msg) {
    super(msg);
  }

  public InvalidSignatureException(String msg, Throwable t) {
    super(msg, t);
  }
}
