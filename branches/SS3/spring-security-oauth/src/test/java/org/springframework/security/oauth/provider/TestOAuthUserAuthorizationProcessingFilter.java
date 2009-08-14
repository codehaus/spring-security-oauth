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

import junit.framework.TestCase;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import static org.easymock.EasyMock.*;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.security.oauth.provider.callback.OAuthCallbackServices;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * @author Ryan Heaton
 */
public class TestOAuthUserAuthorizationProcessingFilter extends TestCase {


  /**
   * tests the attempt to authenticate.
   */
  public void testAttemptAuthentication() throws Exception {
    UserAuthorizationProcessingFilter filter = new UserAuthorizationProcessingFilter("/");
    HttpServletRequest request = createMock(HttpServletRequest.class);
    HttpServletResponse response = createMock(HttpServletResponse.class);
    Authentication authentication = createMock(Authentication.class);
    OAuthProviderTokenServices tokenServices = createMock(OAuthProviderTokenServices.class);
    OAuthCallbackServices callback = createMock(OAuthCallbackServices.class);
    filter.setCallbackServices(callback);

    SecurityContextHolder.getContext().setAuthentication(authentication);
    expect(authentication.isAuthenticated()).andReturn(false);
    expect(request.getParameter("requestToken")).andReturn("tok");
    expect(callback.readCallback("tok")).andReturn("http://my.test.com/test?callback=true&token=tok");
    request.setAttribute(UserAuthorizationProcessingFilter.CALLBACK_ATTRIBUTE, "http://my.test.com/test?callback=true&token=tok");

    replay(authentication, request, tokenServices, callback);

    try {
      filter.attemptAuthentication(request, response);     
      fail();
    }
    catch (InsufficientAuthenticationException e) {
      verify(authentication, request, tokenServices, callback);
      reset(authentication, request, tokenServices, callback);
    }

    expect(authentication.isAuthenticated()).andReturn(true);
    expect(request.getParameter("requestToken")).andReturn("tok");
    expect(callback.readCallback("tok")).andReturn("http://my.test.com/test?callback=true&token=tok");
    request.setAttribute(UserAuthorizationProcessingFilter.CALLBACK_ATTRIBUTE, "http://my.test.com/test?callback=true&token=tok");
    
    tokenServices.authorizeRequestToken("tok", authentication);
    filter.setTokenServices(tokenServices);
    replay(authentication, request, tokenServices, callback);
    filter.attemptAuthentication(request, response);
    verify(authentication, request, tokenServices, callback);
    reset(authentication, request, tokenServices, callback);

    SecurityContextHolder.getContext().setAuthentication(null);
  }



}
