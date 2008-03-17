package org.springframework.security.oauth.provider;

/**
 * @author Ryan Heaton
 */
public class OAuthVersionUnsupportedException extends InvalidOAuthParametersException {

  public OAuthVersionUnsupportedException(String msg) {
    super(msg);
  }
}
