package org.springframework.security.oauth.consumer;

/**
 * Thrown when a different realm appears to be the cause of the authorization failure.
 * 
 * @author Ryan Heaton
 */
public class InvalidOAuthRealmException extends OAuthRequestFailedException {

  private final String requiredRealm;

  public InvalidOAuthRealmException(String msg, String requiredRealm) {
    super(msg);
    this.requiredRealm = requiredRealm;
  }

  public String getRequiredRealm() {
    return requiredRealm;
  }
}
