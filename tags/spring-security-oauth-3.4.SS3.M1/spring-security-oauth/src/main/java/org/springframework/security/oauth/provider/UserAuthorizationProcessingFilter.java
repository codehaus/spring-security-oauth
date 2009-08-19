/*
 * Copyright 2008-2009 Web Cohesion, Andrew McCall
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.provider;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth.provider.callback.OAuthCallbackException;
import org.springframework.security.oauth.provider.callback.OAuthCallbackServices;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Processing filter for handling a request to authenticate an OAuth request token. The default {@link #setFilterProcessesUrl(String) processes URL}
 * is "/oauth_authenticate_token"<br/><br/>
 * <p/>
 * This filter looks for two request parameters, one for the token id and one for the callback URL. The
 * default names of these paramaters are "oauth_token" and "oauth_callback", but this can be configured.<br/><br/>
 * <p/>
 * @author Ryan Heaton
 * @author Andrew McCall
 */
public class UserAuthorizationProcessingFilter extends AbstractAuthenticationProcessingFilter {

  public static final int FILTER_CHAIN_ORDER = UnauthenticatedRequestTokenProcessingFilter.FILTER_CHAIN_ORDER + 1;
  protected static final String CALLBACK_ATTRIBUTE = UserAuthorizationProcessingFilter.class.getName() + "#CALLBACK";

  private OAuthProviderTokenServices tokenServices;
  private String tokenIdParameterName = "requestToken";
  private OAuthCallbackServices callbackServices;
  private boolean require10a = true;
  
  protected UserAuthorizationProcessingFilter(String s) {
    super(s);
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    // call super.
    super.afterPropertiesSet();
    Assert.notNull(getTokenServices(), "A token services must be provided.");
    Assert.notNull(getCallbackServices(), "Callback services are required.");
  }

  public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
    String requestToken = request.getParameter(getTokenParameterName());
    if (requestToken == null) {
      throw new InvalidOAuthParametersException("An OAuth token id is required.");
    }

    String callbackURL = getCallbackServices().readCallback(requestToken);
    if (isRequire10a() && callbackURL == null) {
      throw new OAuthCallbackException("No callback value has been provided for request token " + requestToken + ".");
    }

    if (callbackURL != null) {
      request.setAttribute(CALLBACK_ATTRIBUTE, callbackURL);
    }

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (!authentication.isAuthenticated()) {
      throw new InsufficientAuthenticationException("User must be authenticated before authorizing a request token.");
    }
    getTokenServices().authorizeRequestToken(requestToken, authentication);
    return authentication;
  }

  public String getDefaultFilterProcessesUrl() {
    return "/oauth_authenticate_token";
  }

  /**
   * User authorization comes after the request token.
   *
   * @return The order after the request token.
   */
  public int getOrder() {
    return FILTER_CHAIN_ORDER;
  }

  /**
   * The name of the request parameter that supplies the token id.
   *
   * @return The name of the request parameter that supplies the token id.
   */
  public String getTokenParameterName() {
    return tokenIdParameterName;
  }

  /**
   * The name of the request parameter that supplies the token id.
   *
   * @param tokenIdParameterName The name of the request parameter that supplies the token id.
   */
  public void setTokenIdParameterName(String tokenIdParameterName) {
    this.tokenIdParameterName = tokenIdParameterName;
  }

  /**
   * Get the OAuth token services.
   *
   * @return The OAuth token services.
   */
  public OAuthProviderTokenServices getTokenServices() {
    return tokenServices;
  }

  /**
   * The OAuth token services.
   *
   * @param tokenServices The OAuth token services.
   */
  @Autowired
  public void setTokenServices(OAuthProviderTokenServices tokenServices) {
    this.tokenServices = tokenServices;
  }

  /**
   * The callback services to use.
   *
   * @return The callback services to use.
   */
  public OAuthCallbackServices getCallbackServices() {
    return callbackServices;
  }

  /**
   * The callback services to use.
   *
   * @param callbackServices The callback services to use.
   */
  @Autowired
  public void setCallbackServices(OAuthCallbackServices callbackServices) {
    this.callbackServices = callbackServices;
  }

  /**
   * Whether to require 1.0a support.
   *
   * @return Whether to require 1.0a support.
   */
  public boolean isRequire10a() {
    return require10a;
  }

  /**
   * Whether to require 1.0a support.
   *
   * @param require10a Whether to require 1.0a support.
   */
  public void setRequire10a(boolean require10a) {
    this.require10a = require10a;
  }

}