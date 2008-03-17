package org.springframework.security.oauth.consumer.token;

import org.acegisecurity.AuthenticationException;

/**
 * Token services for an OAuth consumer.
 * 
 * @author Ryan Heaton
 */
public interface OAuthConsumerTokenServices {

  /**
   * Get the token for the specified protected resource.
   *
   * @param resourceId The id of the protected resource.
   * @return The token, or null if none was found.
   */
  OAuthConsumerToken getToken(String resourceId) throws AuthenticationException;

  /**
   * Store a token for a specified resource.
   *
   * @param resourceId The id of the protected resource.
   * @param token The token to store.
   */
  void storeToken(String resourceId, OAuthConsumerToken token);

}
