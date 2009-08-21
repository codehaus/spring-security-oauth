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

import org.springframework.security.AuthenticationException;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.OAuthProviderParameter;
import org.springframework.security.oauth.common.OAuthCodec;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.verifier.OAuthVerifierServices;
import org.springframework.util.Assert;
import org.springframework.beans.factory.annotation.Autowired;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.FilterChain;
import java.util.Map;
import java.io.IOException;

/**
 * Processing filter for handling a request for an OAuth access token.
 *
 * @author Ryan Heaton
 */
public class AccessTokenProcessingFilter extends OAuthProviderProcessingFilter {

  public static final int FILTER_CHAIN_ORDER = UserAuthorizationProcessingFilter.FILTER_CHAIN_ORDER + 1;

  // The OAuth spec doesn't specify a content-type of the response.  However, it's NOT
  // "application/x-www-form-urlencoded" because the response isn't URL-encoded. Until
  // something is specified, we'll assume that it's just "text/plain".
  private String responseContentType = "text/plain;charset=utf-8";

  private OAuthVerifierServices verifierServices;
  private boolean require10a = true;

  public AccessTokenProcessingFilter() {
    setFilterProcessesUrl("/oauth_access_token");
  }

  @Override
  public void afterPropertiesSet() throws Exception {
    super.afterPropertiesSet();
    if (isRequire10a()) {
      Assert.notNull(getVerifierServices(), "Verifier services are required.");
    }
  }

  protected OAuthProviderToken createOAuthToken(ConsumerAuthentication authentication) {
    return getTokenServices().createAccessToken(authentication.getConsumerCredentials().getToken());
  }

  @Override
  protected void validateOAuthParams(ConsumerDetails consumerDetails, Map<String, String> oauthParams) throws InvalidOAuthParametersException {
    super.validateOAuthParams(consumerDetails, oauthParams);

    String token = oauthParams.get(OAuthConsumerParameter.oauth_token.toString());
    if (token == null) {
      throw new InvalidOAuthParametersException(messages.getMessage("AccessTokenProcessingFilter.missingToken", "Missing token."));
    }

    if (isRequire10a()) {
      String verifier = oauthParams.get(OAuthConsumerParameter.oauth_verifier.toString());
      if (verifier == null) {
        throw new InvalidOAuthParametersException(messages.getMessage("AccessTokenProcessingFilter.missingVerifier", "Missing verifier."));
      }
      getVerifierServices().validateVerifier(verifier, token);
    }
  }

  protected void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException {
    //signature is verified; create the token, send the response.
    ConsumerAuthentication authentication = (ConsumerAuthentication) SecurityContextHolder.getContext().getAuthentication();
    OAuthProviderToken authToken = createOAuthToken(authentication);
    if (!authToken.getConsumerKey().equals(authentication.getConsumerDetails().getConsumerKey())) {
      throw new IllegalStateException("The consumer key associated with the created auth token is not valid for the authenticated consumer.");
    }

    String tokenValue = authToken.getValue();

    StringBuilder responseValue = new StringBuilder(OAuthProviderParameter.oauth_token.toString())
      .append('=')
      .append(OAuthCodec.oauthEncode(tokenValue))
      .append('&')
      .append(OAuthProviderParameter.oauth_token_secret.toString())
      .append('=')
      .append(OAuthCodec.oauthEncode(authToken.getSecret()));
    response.setContentType(getResponseContentType());
    response.getWriter().print(responseValue.toString());
    response.flushBuffer();
  }

  @Override
  protected void onNewTimestamp() throws AuthenticationException {
    throw new InvalidOAuthParametersException(messages.getMessage("AccessTokenProcessingFilter.timestampNotNew", "A new timestamp should not be used in a request for an access token."));
  }

  /**
   * The access token filter comes after the user authorization filter.
   *
   * @return The access token filter comes after the user authorization filter.
   */
  public int getOrder() {
    return AccessTokenProcessingFilter.FILTER_CHAIN_ORDER;
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
