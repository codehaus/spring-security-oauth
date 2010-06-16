package org.springframework.security.oauth2.provider;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;

/**
 * An OAuth 2 authentication token can contain multiple authentications: one for the client and one for
 * the user. Since some OAuth flows don't require user authentication, the user authentication may be null.
 *
 * @author Ryan Heaton
 */
public class OAuth2Authentication extends AbstractAuthenticationToken {

  private final Authentication clientAuthentication;
  private final Authentication userAuthentication;

  /**
   * Construct an OAuth 2 authentication. This authentication is presumed to be {@link #isAuthenticated() authenticated}.
   * Since some OAuth flows don't require user authentication, the user authentication may be null.
   *
   * @param clientAuthentication The client authentication (may NOT be null).
   * @param userAuthentication The user authentication (may be null).
   */
  public OAuth2Authentication(Authentication clientAuthentication, Authentication userAuthentication) {
    super(userAuthentication == null ? clientAuthentication.getAuthorities() : userAuthentication.getAuthorities());
    this.clientAuthentication = clientAuthentication;
    this.userAuthentication = userAuthentication;
    setAuthenticated(true);
  }

  public Object getCredentials() {
    return this.userAuthentication == null ? this.clientAuthentication.getCredentials() : this.userAuthentication.getCredentials();
  }

  public Object getPrincipal() {
    return this.userAuthentication == null ? this.clientAuthentication.getPrincipal() : this.userAuthentication.getPrincipal();
  }

  public Authentication getClientAuthentication() {
    return clientAuthentication;
  }

  public Authentication getUserAuthentication() {
    return userAuthentication;
  }
}
