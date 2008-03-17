package org.springframework.security.oauth.consumer.token;

import org.acegisecurity.AuthenticationException;

import javax.servlet.http.HttpSession;

/**
 * Stores the tokens in an HTTP session.
 *
 * @author Ryan Heaton
 */
public class HttpSessionBasedTokenServices implements OAuthConsumerTokenServices {

  public static final String KEY_PREFIX = "OAUTH_TOKEN";

  private final HttpSession session;

  public HttpSessionBasedTokenServices(HttpSession session) {
    this.session = session;
  }

  public OAuthConsumerToken getToken(String resourceId) throws AuthenticationException {
    return (OAuthConsumerToken) this.session.getAttribute(KEY_PREFIX + "#" + resourceId);
  }

  public void storeToken(String resourceId, OAuthConsumerToken token) {
    this.session.setAttribute(KEY_PREFIX + "#" + resourceId, token);
  }
}
