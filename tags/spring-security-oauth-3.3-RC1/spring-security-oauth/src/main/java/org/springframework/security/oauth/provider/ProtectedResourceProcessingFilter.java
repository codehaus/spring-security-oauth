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
import org.springframework.security.AccessDeniedException;
import org.springframework.security.providers.AbstractAuthenticationToken;
import org.springframework.security.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Map;

/**
 * Processing filter for requests to protected resources. This filter attempts to load the OAuth authentication
 * request into the security context using a presented access token.  Default behavior of this filter allows
 * the request to continue even if OAuth credentials are not presented (allowing another filter to potentially
 * load a different authentication request into the security context). If the protected resource is available
 * ONLY via OAuth access token, set <code>requireOAuthCredentials</code> to true. 
 *
 * @author Ryan Heaton
 */
public class ProtectedResourceProcessingFilter extends OAuthProviderProcessingFilter {

  public static final int FILTER_CHAIN_ORDER = AccessTokenProcessingFilter.FILTER_CHAIN_ORDER + 1;

  private boolean allowAllMethods = true;

  public ProtectedResourceProcessingFilter() {
    //we're going to ignore missing credentials by default.  This is to allow a chance for the resource to
    //be accessed by some other means of authentication.
    setIgnoreMissingCredentials(true);
  }

  @Override
  protected boolean allowMethod(String method) {
    return allowAllMethods || super.allowMethod(method);
  }

  protected void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException {
    ConsumerAuthentication authentication = (ConsumerAuthentication) SecurityContextHolder.getContext().getAuthentication();
    OAuthProviderToken authToken = getTokenServices().getToken(authentication.getConsumerCredentials().getToken());
    if (authToken == null) {
      throw new AccessDeniedException("Invalid access token.");
    }
    else if (!authToken.isAccessToken()) {
      throw new AccessDeniedException("Token should be an access token.");
    }
    else {
      Authentication userAuthentication = ((OAuthAccessProviderToken) authToken).getUserAuthentication();
      if (userAuthentication instanceof AbstractAuthenticationToken) {
        //initialize the details with the consumer that is actually making the request on behalf of the user.
        ((AbstractAuthenticationToken) userAuthentication).setDetails(new OAuthAuthenticationDetails(request, authentication.getConsumerDetails()));
      }
      SecurityContextHolder.getContext().setAuthentication(userAuthentication);
    }
    chain.doFilter(request, response);
  }

  @Override
  protected void validateOAuthParams(ConsumerDetails consumerDetails, Map<String, String> oauthParams) throws InvalidOAuthParametersException {
    super.validateOAuthParams(consumerDetails, oauthParams);

    String token = oauthParams.get(OAuthConsumerParameter.oauth_token.toString());
    if (token == null) {
      throw new InvalidOAuthParametersException(messages.getMessage("ProtectedResourceProcessingFilter.missingToken", "Missing auth token."));
    }
  }

  @Override
  protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
    return true;
  }

  @Override
  public void setFilterProcessesUrl(String filterProcessesUrl) {
    throw new UnsupportedOperationException("The OAuth protected resource processing filter doesn't support a filter processes URL.");
  }

  /**
   * The protected resource filtering happens after the access token filtering.
   *
   * @return The order after the access token.
   */
  public int getOrder() {
    return ProtectedResourceProcessingFilter.FILTER_CHAIN_ORDER;
  }

  /**
   * Whether to allow all methods.
   *
   * @return Whether to allow all methods.
   */
  public boolean isAllowAllMethods() {
    return allowAllMethods;
  }

  /**
   * Whether to allow all methods.
   *
   * @param allowAllMethods Whether to allow all methods.
   */
  public void setAllowAllMethods(boolean allowAllMethods) {
    this.allowAllMethods = allowAllMethods;
  }

}