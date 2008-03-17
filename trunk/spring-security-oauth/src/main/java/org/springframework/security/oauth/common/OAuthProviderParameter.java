package org.springframework.security.oauth.common;

/**
 * Parameters that can be used by the provider.
 *
 * @author Ryan Heaton
 */
public enum OAuthProviderParameter {

  /**
   * The oauth token.
   */
  oauth_token,

  /**
   * The oauth token secret.
   */
  oauth_token_secret
}
