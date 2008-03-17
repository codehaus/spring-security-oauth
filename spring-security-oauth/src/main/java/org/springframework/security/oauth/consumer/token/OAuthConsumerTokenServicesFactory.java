package org.springframework.security.oauth.consumer.token;

import org.acegisecurity.Authentication;

import javax.servlet.http.HttpServletRequest;

/**
 * Factory for token services.
 *
 * @author Ryan Heaton
 */
public interface OAuthConsumerTokenServicesFactory {

  /**
   * Get the token services for the specified request and authentication.
   *
   * @param authentication The authentication.
   * @param request The request
   * @return The token services.
   */
  OAuthConsumerTokenServices getTokenServices(Authentication authentication, HttpServletRequest request);
}
