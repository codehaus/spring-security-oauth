package org.springframework.security.oauth.provider;

import junit.framework.TestCase;
import org.acegisecurity.Authentication;
import org.acegisecurity.InsufficientAuthenticationException;
import org.acegisecurity.context.SecurityContextHolder;
import static org.easymock.EasyMock.*;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;

import javax.servlet.http.HttpServletRequest;

/**
 * @author Ryan Heaton
 */
public class TestOAuthUserAuthorizationProcessingFilter extends TestCase {

  /**
   * tests the attempt to authenticate.
   */
  public void testAttemptAuthentication() throws Exception {
    UserAuthorizationProcessingFilter filter = new UserAuthorizationProcessingFilter();
    HttpServletRequest request = createMock(HttpServletRequest.class);
    Authentication authentication = createMock(Authentication.class);
    OAuthProviderTokenServices tokenServices = createMock(OAuthProviderTokenServices.class);

    SecurityContextHolder.getContext().setAuthentication(authentication);
    expect(authentication.isAuthenticated()).andReturn(false);
    replay(authentication, request, tokenServices);
    try {
      filter.attemptAuthentication(request);
      fail();
    }
    catch (InsufficientAuthenticationException e) {
      verify(authentication, request, tokenServices);
      reset(authentication, request, tokenServices);
    }

    expect(authentication.isAuthenticated()).andReturn(true);
    expect(request.getParameter("oauth_token")).andReturn("tok");
    tokenServices.authorizeRequestToken("tok", authentication);
    filter.setTokenServices(tokenServices);
    replay(authentication, request, tokenServices);
    filter.attemptAuthentication(request);
    verify(authentication, request, tokenServices);
    reset(authentication, request, tokenServices);

    SecurityContextHolder.getContext().setAuthentication(null);
  }

  /**
   * test determineTargetUrl
   */
  public void testDetermineTargetUrl() throws Exception {
    UserAuthorizationProcessingFilter filter = new UserAuthorizationProcessingFilter();
    HttpServletRequest request = createMock(HttpServletRequest.class);

    expect(request.getParameter("oauth_callback")).andReturn("http://my.host.com/my/context");
    expect(request.getParameter("oauth_token")).andReturn("mytok");
    replay(request);
    assertEquals("http://my.host.com/my/context?oauth_token=mytok", filter.determineTargetUrl(request));
    verify(request);
    reset(request);

    expect(request.getParameter("oauth_callback")).andReturn("http://my.host.com/my/context?with=some&query=parameter");
    expect(request.getParameter("oauth_token")).andReturn("mytok");
    replay(request);
    assertEquals("http://my.host.com/my/context?with=some&query=parameter&oauth_token=mytok", filter.determineTargetUrl(request));
    verify(request);
    reset(request);
  }

}
