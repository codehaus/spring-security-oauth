package org.springframework.security.oauth.provider.token;

import org.springframework.security.oauth.common.OAuthException;

/**
 * @author Ryan Heaton
 */
public class InvalidOAuthTokenException extends OAuthException {

  public InvalidOAuthTokenException(String msg) {
    super(msg);
  }
}
