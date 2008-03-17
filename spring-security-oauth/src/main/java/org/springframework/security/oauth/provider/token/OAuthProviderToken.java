package org.springframework.security.oauth.provider.token;

import java.io.Serializable;

/**
 * @author Ryan Heaton
 */
public interface OAuthProviderToken extends Serializable {
  /**
   * The value of the token.
   *
   * @return The value of the token.
   */
  String getValue();

  /**
   * The token secret.
   *
   * @return The token secret.
   */
  String getSecret();

  /**
   * The consumer key associated with this oauth token.
   *
   * @return The consumer key associated with this oauth token.
   */
  String getConsumerKey();

  /**
   * Whether this is an OAuth access token.
   *
   * @return Whether this is an OAuth access token.
   */
  boolean isAccessToken();
}
