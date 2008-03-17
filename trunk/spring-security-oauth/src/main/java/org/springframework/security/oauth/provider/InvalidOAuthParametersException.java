package org.springframework.security.oauth.provider;

import org.springframework.security.oauth.common.OAuthException;

/**
 * @author Ryan Heaton
 */
public class InvalidOAuthParametersException extends OAuthException {

  public InvalidOAuthParametersException(String msg) {
    super(msg);
  }
}
