package org.springframework.security.oauth.provider;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.context.SecurityContextHolder;
import org.springframework.security.oauth.common.OAuthCodec;
import org.springframework.security.oauth.common.OAuthProviderParameter;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Processing filter for handling a request for an OAuth token. The default implementation assumes a request for a new
 * unauthenticated request token.
 *
 * @author Ryan Heaton
 */
public class UnauthenticatedRequestTokenProcessingFilter extends OAuthProviderProcessingFilter {

  // The OAuth spec doesn't specify a content-type of the response.  However, it's NOT
  // "application/x-www-form-urlencoded" because the response isn't URL-encoded. Until
  // something is specified, we'll assume that it's just "text/plain".
  private String responseContentType = "text/plain;charset=utf-8";

  public UnauthenticatedRequestTokenProcessingFilter() {
    setFilterProcessesUrl("/oauth_request_token");
  }

  protected void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException {
    //signature is verified; create the token, send the response.
    ConsumerAuthentication authentication = (ConsumerAuthentication) SecurityContextHolder.getContext().getAuthentication();
    OAuthProviderToken authToken = createOAuthToken(authentication);
    if (!authToken.getConsumerKey().equals(authentication.getConsumerDetails().getConsumerKey())) {
      throw new IllegalStateException("The consumer key associated with the created auth token is not valid for the authenticated consumer.");
    }

    StringBuilder responseValue = new StringBuilder(OAuthProviderParameter.oauth_token.toString())
      .append('=')
      .append(OAuthCodec.oauthEncode(authToken.getValue()))
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
}