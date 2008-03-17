package org.springframework.security.oauth.consumer.token;

import org.acegisecurity.Authentication;

import javax.servlet.http.HttpServletRequest;

/**
 * Stores the tokens in an HTTP session.
 *
 * @author Ryan Heaton
 */
public class HttpSessionBasedTokenServicesFactory implements OAuthConsumerTokenServicesFactory {

  public OAuthConsumerTokenServices getTokenServices(Authentication authentication, HttpServletRequest request) {
    return new HttpSessionBasedTokenServices(request.getSession(true));
  }
}