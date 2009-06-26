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

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.AuthenticationException;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthCodec;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.OAuthProviderParameter;
import org.springframework.security.oauth.provider.callback.OAuthCallbackServices;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.ui.FilterChainOrder;
import org.springframework.util.Assert;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * Processing filter for handling a request for an OAuth token. The default implementation assumes a request for a new
 * unauthenticated request token. The default {@link #setFilterProcessesUrl(String) processes URL} is "/oauth_request_token".
 *
 * @author Ryan Heaton
 */
public class UnauthenticatedRequestTokenProcessingFilter extends OAuthProviderProcessingFilter {

  public static final int FILTER_CHAIN_ORDER = FilterChainOrder.EXCEPTION_TRANSLATION_FILTER + 15;

  // The OAuth spec doesn't specify a content-type of the response.  However, it's NOT
  // "application/x-www-form-urlencoded" because the response isn't URL-encoded. Until
  // something is specified, we'll assume that it's just "text/plain".
  private String responseContentType = "text/plain;charset=utf-8";

  private OAuthCallbackServices callbackServices;

  public UnauthenticatedRequestTokenProcessingFilter() {
    setFilterProcessesUrl("/oauth_request_token");
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    super.afterPropertiesSet();
    Assert.notNull(getCallbackServices(), "Callback services are required.");
  }

  @Override
  protected void validateOAuthParams(ConsumerDetails consumerDetails, Map<String, String> oauthParams) throws InvalidOAuthParametersException {
    super.validateOAuthParams(consumerDetails, oauthParams);

    String token = oauthParams.get(OAuthConsumerParameter.oauth_callback.toString());
    if (token == null) {
      throw new InvalidOAuthParametersException(messages.getMessage("AccessTokenProcessingFilter.missingCallback", "Missing callback."));
    }
  }

  protected void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException {
    //signature is verified; create the token, send the response.
    ConsumerAuthentication authentication = (ConsumerAuthentication) SecurityContextHolder.getContext().getAuthentication();
    OAuthProviderToken authToken = createOAuthToken(authentication);
    if (!authToken.getConsumerKey().equals(authentication.getConsumerDetails().getConsumerKey())) {
      throw new IllegalStateException("The consumer key associated with the created auth token is not valid for the authenticated consumer.");
    }

    //store the callback url.
    String tokenValue = authToken.getValue();
    getCallbackServices().storeCallback(authentication.getOAuthParameters().get(OAuthConsumerParameter.oauth_callback.toString()), tokenValue);

    StringBuilder responseValue = new StringBuilder(OAuthProviderParameter.oauth_token.toString())
      .append('=')
      .append(OAuthCodec.oauthEncode(tokenValue))
      .append('&')
      .append(OAuthProviderParameter.oauth_token_secret.toString())
      .append('=')
      .append(OAuthCodec.oauthEncode(authToken.getSecret()))
      .append('&')
      .append(OAuthProviderParameter.oauth_callback_confirmed.toString())
      .append("=true");
    response.setContentType(getResponseContentType());
    response.getWriter().print(responseValue.toString());
    response.flushBuffer();
  }

  @Override
  protected void onNewTimestamp() throws AuthenticationException {
    //no-op. A new timestamp should be supplied for a request for a new unauthenticated request token.
  }

  /**
   * Create the OAuth token for the specified consumer key.
   *
   * @param authentication The authentication request.
   * @return The OAuth token.
   */
  protected OAuthProviderToken createOAuthToken(ConsumerAuthentication authentication) {
    return getTokenServices().createUnauthorizedRequestToken(authentication.getConsumerDetails().getConsumerKey());
  }

  /**
   * The request token filter comes after the exception translation filter.
   *
   * @return The request token filter comes after the exception translation filter.
   */
  public int getOrder() {
    return FILTER_CHAIN_ORDER;
  }

  /**
   * The content type of the response.
   *
   * @return The content type of the response.
   */
  public String getResponseContentType() {
    return responseContentType;
  }

  /**
   * The content type of the response.
   *
   * @param responseContentType The content type of the response.
   */
  public void setResponseContentType(String responseContentType) {
    this.responseContentType = responseContentType;
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
}