package org.springframework.security.oauth.provider.token;

import org.springframework.security.oauth.common.OAuthException;

/**
 * @author Ryan Heaton
 */
public class ExpiredOAuthTokenException extends OAuthException {

  public ExpiredOAuthTokenException(String msg) {
    super(msg);
  }
}