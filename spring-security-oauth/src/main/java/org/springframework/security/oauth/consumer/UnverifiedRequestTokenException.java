package org.springframework.security.oauth.consumer;

/**
 * Thrown when an attempt is made to use an unverified request token.
 *
 * @author Ryan Heaton
 */
public class UnverifiedRequestTokenException extends OAuthRequestFailedException {

  public UnverifiedRequestTokenException(String msg) {
    super(msg);
  }

  public UnverifiedRequestTokenException(String msg, Throwable t) {
    super(msg, t);
  }
}