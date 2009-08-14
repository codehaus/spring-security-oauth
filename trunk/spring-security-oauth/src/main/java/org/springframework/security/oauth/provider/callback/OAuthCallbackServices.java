package org.springframework.security.oauth.provider.callback;

/**
 * Services for persisting a callback for a given request token.
 *
 * @author Ryan Heaton
 */
public interface OAuthCallbackServices {

  /**
   * Services used to store a callback url.
   *
   * @param callback The callback URL to store.
   * @param requestToken The request token to which the callback is associated.
   */
  void storeCallback(String callback, String requestToken) throws OAuthCallbackException;

  /**
   * Read the callback for the specified request token.
   *
   * @param requestToken The request token.
   * @return The callback URL, or null if none found.
   */
  String readCallback(String requestToken) throws OAuthCallbackException;
}
