/*
 * Copyright 2009 Andrew McCall
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

import org.springframework.security.oauth.provider.verifier.OAuthVerifierServices;
import static org.easymock.EasyMock.*;
import static org.easymock.EasyMock.verify;
import static org.easymock.EasyMock.reset;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import junit.framework.TestCase;


/**
 * @author Andrew McCall
 */
public class TestUserAuthorizationSuccessfulAuthenticationHandler extends TestCase {


  /**
   * test determineTargetUrl
   */
  public void testAuthenticationSuccess() throws Exception {


    UserAuthorizationSuccessfulAuthenticationHandler handler = new UserAuthorizationSuccessfulAuthenticationHandler();
    OAuthVerifierServices vs = createMock(OAuthVerifierServices.class);
    HttpServletRequest request = createMock(HttpServletRequest.class);
    HttpServletResponse response = createMock(HttpServletResponse.class);

    expect(request.getAttribute(UserAuthorizationProcessingFilter.CALLBACK_ATTRIBUTE)).andReturn("http://my.host.com/my/context");
    expect(request.getAttribute(UserAuthorizationProcessingFilter.VERIFIER_ATTRIBUTE)).andReturn("myver");
    expect(request.getParameter("requestToken")).andReturn("mytok");

    expect(response.encodeRedirectURL("http://my.host.com/my/context?oauth_token=mytok&oauth_verifier=myver")).andReturn("http://my.host.com/my/context?oauth_token=mytok&oauth_verifier=myver");
    response.sendRedirect("http://my.host.com/my/context?oauth_token=mytok&oauth_verifier=myver");

    replay(response, request, vs);

    handler.onAuthenticationSuccess(request, response, null);

    verify(response, request, vs);
    reset(response, request, vs);

    handler = new UserAuthorizationSuccessfulAuthenticationHandler();

    expect(request.getAttribute(UserAuthorizationProcessingFilter.CALLBACK_ATTRIBUTE)).andReturn("http://my.hosting.com/my/context?with=some&query=parameter");
    expect(request.getAttribute(UserAuthorizationProcessingFilter.VERIFIER_ATTRIBUTE)).andReturn("myvera");
    expect(request.getParameter("requestToken")).andReturn("mytoka");

    expect(response.encodeRedirectURL("http://my.hosting.com/my/context?with=some&query=parameter&oauth_token=mytoka&oauth_verifier=myvera")).andReturn("http://my.hosting.com/my/context?with=some&query=parameter&oauth_token=mytoka&oauth_verifier=myvera");
    response.sendRedirect("http://my.hosting.com/my/context?with=some&query=parameter&oauth_token=mytoka&oauth_verifier=myvera");

    replay(response, request, vs);

    handler.onAuthenticationSuccess(request, response, null);
   
    verify(response, request, vs);
    reset(response, request, vs);

  }
}
