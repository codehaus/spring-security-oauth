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
