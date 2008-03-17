package org.springframework.security.oauth.consumer;

import org.springframework.security.oauth.common.OAuthException;

/**
 * Thrown when an OAuth request fails.
 *
 * @author Ryan Heaton
 */
public class OAuthRequestFailedException extends OAuthException {

  public OAuthRequestFailedException(String msg) {
    super(msg);
  }

  public OAuthRequestFailedException(String msg, Throwable t) {
    super(msg, t);
  }
}
