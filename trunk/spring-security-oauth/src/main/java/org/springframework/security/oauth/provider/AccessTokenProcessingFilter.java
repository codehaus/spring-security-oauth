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

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.BadCredentialsException;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;

import java.util.Map;

/**
 * Processing filter for handling a request for an OAuth access token.
 *
 * @author Ryan Heaton
 */
public class AccessTokenProcessingFilter extends UnauthenticatedRequestTokenProcessingFilter {

  public AccessTokenProcessingFilter() {
    setFilterProcessesUrl("/oauth_access_token");
  }

  @Override
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
  }

  @Override
  protected void onNewTimestamp() throws AuthenticationException {
    throw new InvalidOAuthParametersException(messages.getMessage("AccessTokenProcessingFilter.timestampNotNew", "A new timestamp should not be used in a request for an access token."));
  }
}
