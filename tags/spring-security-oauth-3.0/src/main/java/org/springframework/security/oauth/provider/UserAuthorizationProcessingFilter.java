/*
 * Copyright 2008 Web Cohesion
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

import org.springframework.security.Authentication;
import org.springframework.security.AuthenticationException;
import org.springframework.security.InsufficientAuthenticationException;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.security.oauth.provider.callback.OAuthCallbackServices;
import org.springframework.security.oauth.provider.callback.OAuthCallbackException;
import org.springframework.security.oauth.provider.verifier.OAuthVerifierServices;
import org.springframework.security.ui.AbstractProcessingFilter;
import org.springframework.util.Assert;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Processing filter for handling a request to authenticate an OAuth request token. The default {@link #setFilterProcessesUrl(String) processes URL}
 * is "/oauth_authenticate_token"<br/><br/>
 *
 * This filter looks for two request parameters, one for the token id and one for the callback URL. The
 * default names of these paramaters are "oauth_token" and "oauth_callback", but this can be configured.<br/><br/>
 *
 * Upon successful authorization of the request token, the response is a redirect back to the callback, if supplied.
 * Otherwise, the response is a redirect to the {@link #setDefaultTargetUrl(String) default target URL}. Upon failure
 * to authorize, the response is a redirect to {@link #setAuthenticationFailureUrl(String) failure URL}.
 *
 *
 * @author Ryan Heaton
 */
public class UserAuthorizationProcessingFilter extends AbstractProcessingFilter {

  public static final int FILTER_CHAIN_ORDER = UnauthenticatedRequestTokenProcessingFilter.FILTER_CHAIN_ORDER + 1;
  protected static final String CALLBACK_ATTRIBUTE = UserAuthorizationProcessingFilter.class.getName() + "#CALLBACK";

  private OAuthProviderTokenServices tokenServices;
  private String tokenIdParameterName = "requestToken";
  private String callbackParameterName = "callbackURL";
  private OAuthCallbackServices callbackServices;
  private OAuthVerifierServices verifierServices;

  public UserAuthorizationProcessingFilter() {
    setDefaultTargetUrl("/");
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    Assert.notNull(getRememberMeServices());
    Assert.notNull(getTokenServices(), "A token services must be provided.");
    Assert.notNull(getCallbackServices(), "Callback services are required.");
    Assert.notNull(getVerifierServices(), "Verifier services are required.");
  }

  @Override
  protected void onPreAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException {
    String requestToken = request.getParameter(getTokenParameterName());
    if (requestToken == null) {
      throw new InvalidOAuthParametersException("An OAuth token id is required.");
    }

    String callbackURL = getCallbackServices().readCallback(requestToken);
    if (callbackURL == null) {
      throw new OAuthCallbackException("No callback value has been provided for request token " + requestToken + ".");
    }
    request.setAttribute(CALLBACK_ATTRIBUTE, callbackURL);
  }

  public Authentication attemptAuthentication(HttpServletRequest request) throws AuthenticationException {
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    if (!authentication.isAuthenticated()) {
      throw new InsufficientAuthenticationException("User must be authenticated before authorizing a request token.");
    }
    getTokenServices().authorizeRequestToken(request.getParameter(getTokenParameterName()), authentication);
    return authentication;
  }

  @Override
  protected String determineTargetUrl(HttpServletRequest request) {
    String callbackURL = (String) request.getAttribute(CALLBACK_ATTRIBUTE);
    if (callbackURL == null) {
      throw new IllegalStateException("Callback URL was not loaded into the request. onPreAuthentication() never called?");
    }

    if ("oob".equals(callbackURL)) {
      return super.determineTargetUrl(request);
    }
    else {
      String requestToken = request.getParameter(getTokenParameterName());
      String verifier = getVerifierServices().createVerifier(requestToken);
      char appendChar = '?';
      if (callbackURL.indexOf('?') > 0) {
        appendChar = '&';
      }
      return new StringBuilder(callbackURL).append(appendChar).append("oauth_token=").append(requestToken).append("&oauth_verifier=").append(verifier).toString();
    }
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
    return UserAuthorizationProcessingFilter.FILTER_CHAIN_ORDER;
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
   * The name of the request parameter that supplies the callback URL.
   *
   * @return The name of the request parameter that supplies the callback URL.
   */
  public String getCallbackParameterName() {
    return callbackParameterName;
  }

  /**
   * The name of the request parameter that supplies the callback URL.
   *
   * @param callbackParameterName The name of the request parameter that supplies the callback URL.
   */
  public void setCallbackParameterName(String callbackParameterName) {
    this.callbackParameterName = callbackParameterName;
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
   * The verifier services to use.
   *
   * @return The verifier services to use.
   */
  public OAuthVerifierServices getVerifierServices() {
    return verifierServices;
  }

  /**
   * The verifier services to use.
   *
   * @param verifierServices The verifier services to use.
   */
  @Autowired
  public void setVerifierServices(OAuthVerifierServices verifierServices) {
    this.verifierServices = verifierServices;
  }  
}