package org.springframework.security.oauth.common;

import org.acegisecurity.AuthenticationException;

/**
 * Base exception for OAuth processing.
 * 
 * @author Ryan Heaton
 */
public class OAuthException extends AuthenticationException {

  public OAuthException(String message) {
    super(message);
  }

  public OAuthException(String message, Throwable throwable) {
    super(message, throwable);
  }
}
