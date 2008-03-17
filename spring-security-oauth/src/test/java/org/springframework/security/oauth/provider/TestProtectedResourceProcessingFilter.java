package org.springframework.security.oauth.provider;

import junit.framework.TestCase;
import org.acegisecurity.Authentication;
import org.acegisecurity.context.SecurityContextHolder;
import static org.easymock.EasyMock.*;
import org.springframework.security.oauth.provider.token.OAuthAccessProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;

import javax.servlet.FilterChain;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Ryan Heaton
 */
public class TestProtectedResourceProcessingFilter extends TestCase {

  /**
   * test onValidSignature
   */
  public void testOnValidSignature() throws Exception {
    ProtectedResourceProcessingFilter filter = new ProtectedResourceProcessingFilter();
    HttpServletRequest request = createMock(HttpServletRequest.class);
    HttpServletResponse response = createMock(HttpServletResponse.class);
    FilterChain chain = createMock(FilterChain.class);
    ConsumerCredentials creds = new ConsumerCredentials("key", "sig", "meth", "base", "tok");
    ConsumerAuthentication authentication = new ConsumerAuthentication(null, creds);
    authentication.setAuthenticated(true);
    SecurityContextHolder.getContext().setAuthentication(authentication);
    OAuthProviderTokenServices tokenServices = createMock(OAuthProviderTokenServices.class);
    OAuthAccessProviderToken token = createMock(OAuthAccessProviderToken.class);
    filter.setTokenServices(tokenServices);

    expect(tokenServices.getToken("tok")).andReturn(token);
    expect(token.isAccessToken()).andReturn(true);
    Authentication userAuthentication = createNiceMock(Authentication.class);
    expect(token.getUserAuthentication()).andReturn(userAuthentication);
    chain.doFilter(request, response);
    replay(request, response, chain, tokenServices, token);
    filter.onValidSignature(request, response, chain);
    assertSame(userAuthentication, SecurityContextHolder.getContext().getAuthentication());
    verify(request, response, chain, tokenServices, token);
    reset(request, response, chain, tokenServices, token);

    SecurityContextHolder.getContext().setAuthentication(null);
  }

}
