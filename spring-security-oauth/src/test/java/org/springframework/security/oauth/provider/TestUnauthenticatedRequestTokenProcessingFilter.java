package org.springframework.security.oauth.provider;

import static org.easymock.EasyMock.*;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;
import org.acegisecurity.context.SecurityContextHolder;

import junit.framework.TestCase;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.FilterChain;
import java.io.StringWriter;
import java.io.PrintWriter;

/**
 * @author Ryan Heaton
 */
public class TestUnauthenticatedRequestTokenProcessingFilter extends TestCase {

  /**
   * test onValidSignature
   */
  public void testOnValidSignature() throws Exception {
    final OAuthProviderToken authToken = createMock(OAuthProviderToken.class);
    UnauthenticatedRequestTokenProcessingFilter filter = new UnauthenticatedRequestTokenProcessingFilter() {
      @Override
      protected OAuthProviderToken createOAuthToken(ConsumerAuthentication authentication) {
        return authToken;
      }
    };
    HttpServletRequest request = createMock(HttpServletRequest.class);
    HttpServletResponse response = createMock(HttpServletResponse.class);
    FilterChain filterChain = createMock(FilterChain.class);
    ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
    ConsumerDetails consumerDetails = createMock(ConsumerDetails.class);
    ConsumerAuthentication authentication = new ConsumerAuthentication(consumerDetails, creds);
    authentication.setAuthenticated(true);
    SecurityContextHolder.getContext().setAuthentication(authentication);

    expect(authToken.getConsumerKey()).andReturn("chi");
    expect(authToken.getValue()).andReturn("tokvalue");
    expect(authToken.getSecret()).andReturn("shhhhhh");
    expect(consumerDetails.getConsumerKey()).andReturn("chi");
    response.setContentType("text/plain;charset=utf-8");
    StringWriter writer = new StringWriter();
    expect(response.getWriter()).andReturn(new PrintWriter(writer));
    response.flushBuffer();
    replay(request, response, filterChain, authToken, consumerDetails);
    filter.onValidSignature(request, response, filterChain);
    assertEquals("oauth_token=tokvalue&oauth_token_secret=shhhhhh", writer.toString());
    verify(request, response, filterChain, authToken, consumerDetails);
    reset(request, response, filterChain, authToken, consumerDetails);

    SecurityContextHolder.getContext().setAuthentication(null);
  }

  /**
   * tests creating the oauth token.
   */
  public void testCreateOAuthToken() throws Exception {
    ConsumerDetails consumerDetails = createMock(ConsumerDetails.class);
    ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
    ConsumerAuthentication authentication = new ConsumerAuthentication(consumerDetails, creds);
    OAuthProviderTokenServices tokenServices = createMock(OAuthProviderTokenServices.class);
    OAuthAccessProviderToken token = createMock(OAuthAccessProviderToken.class);

    UnauthenticatedRequestTokenProcessingFilter filter = new UnauthenticatedRequestTokenProcessingFilter();
    filter.setTokenServices(tokenServices);

    expect(consumerDetails.getConsumerKey()).andReturn("chi");
    expect(tokenServices.createUnauthorizedRequestToken("chi")).andReturn(token);
    replay(consumerDetails, tokenServices, token);
    assertSame(token, filter.createOAuthToken(authentication));
    verify(consumerDetails, tokenServices, token);
    reset(consumerDetails, tokenServices, token);
  }

}
