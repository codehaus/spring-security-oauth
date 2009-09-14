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

import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.util.RedirectUtils;
import org.springframework.security.core.Authentication;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.ServletException;
import java.io.IOException;

import static org.springframework.security.oauth.provider.UserAuthorizationProcessingFilter.CALLBACK_ATTRIBUTE;
import org.springframework.security.oauth.provider.callback.OAuthCallbackServices;
import org.springframework.security.oauth.provider.verifier.OAuthVerifierServices;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.Assert;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Successful AuthenticationHandler that gets called when a user complete authorization of a resource.
 *
 * If the callback URL is oob, the request is handled by the SimpleUrlAuthenticationSuccessHandler using the default
 * success URL. Otherwise, the oauth_verifier and oauth_token parmeters are appended to the callback URL and the user
 * is redirected.
 *
 * @author Andrew McCall
 */
public class UserAuthorizationSuccessfulAuthenticationHandler extends SimpleUrlAuthenticationSuccessHandler implements org.springframework.beans.factory.InitializingBean {

  private static Log LOG = LogFactory.getLog(UserAuthorizationSuccessfulAuthenticationHandler.class);

  private OAuthCallbackServices callbackServices;
  private OAuthVerifierServices verifierServices;
  private String tokenIdParameterName = "requestToken";
  private String callbackParameterName = "callbackURL";
  private boolean require10a = true;

  public UserAuthorizationSuccessfulAuthenticationHandler() {
    super();
  }

  public UserAuthorizationSuccessfulAuthenticationHandler(String s) {
    super(s);
  }

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(getCallbackServices(), "Callback services are required.");
    Assert.notNull(getVerifierServices(), "Verifier services are required.");
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Processing successful authentication successful");
    }

    String callbackURL = (String) request.getAttribute(CALLBACK_ATTRIBUTE);
    if (callbackURL == null) {
      if (!isRequire10a()) {
        callbackURL = request.getParameter(getCallbackParameterName());
        if (callbackURL == null) {
          //if we're not requiring 1.0a, then not providing a callback url is the same as stating 'oob'
          callbackURL = "oob";
        }
      }
      else {
        throw new IllegalStateException("Callback URL was not loaded into the request. attemptAuthentication() never called?");
      }
    }

    if ("oob".equals(callbackURL)) {
      super.onAuthenticationSuccess(request, response, authentication);
    }
    else {
      if (LOG.isDebugEnabled()) {
        LOG.debug("Storing verifier.");
      }
      String requestToken = request.getParameter(getTokenParameterName());
      String verifier = getVerifierServices().createVerifier(requestToken);
      char appendChar = '?';
      if (callbackURL.indexOf('?') > 0) {
        appendChar = '&';
      }
      String targetUrl = new StringBuilder(callbackURL).append(appendChar).append("oauth_token=").append(requestToken).append("&oauth_verifier=").append(verifier).toString();

      RedirectUtils.sendRedirect(request, response, targetUrl, this.isUseRelativeContext());
    }
  }

  /**
   * The name of the request parameter that supplies the token id.
   *
   * @return The name of the request parameter that supplies the token id.
   */
  public String getTokenParameterName() {
    return tokenIdParameterName;
  }

  /**
   * The name of the request parameter that supplies the token id.
   *
   * @param tokenIdParameterName The name of the request parameter that supplies the token id.
   */
  public void setTokenIdParameterName(String tokenIdParameterName) {
    this.tokenIdParameterName = tokenIdParameterName;
  }


  /**
   * The callback services to use.
   *
   * @return The callback services to use.
   */
  public OAuthCallbackServices getCallbackServices() {
    return callbackServices;
  }

  /**
   * The callback services to use.
   *
   * @param callbackServices The callback services to use.
   */
  @Autowired
  public void setCallbackServices(OAuthCallbackServices callbackServices) {
    this.callbackServices = callbackServices;
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

  /**
   * The name of the request parameter that supplies the callback URL.
   *
   * @return The name of the request parameter that supplies the callback URL.
   */
  public String getCallbackParameterName() {
    return callbackParameterName;
  }

  /**
   * The name of the request parameter that supplies the callback URL.
   *
   * @param callbackParameterName The name of the request parameter that supplies the callback URL.
   */
  public void setCallbackParameterName(String callbackParameterName) {
    this.callbackParameterName = callbackParameterName;
  }

}