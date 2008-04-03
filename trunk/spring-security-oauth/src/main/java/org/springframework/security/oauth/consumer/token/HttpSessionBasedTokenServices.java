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

package org.springframework.security.oauth.consumer.token;

import org.acegisecurity.AuthenticationException;

import javax.servlet.http.HttpSession;

/**
 * Stores the tokens in an HTTP session.
 *
 * @author Ryan Heaton
 */
public class HttpSessionBasedTokenServices implements OAuthConsumerTokenServices {

  public static final String KEY_PREFIX = "OAUTH_TOKEN";

  private final HttpSession session;

  public HttpSessionBasedTokenServices(HttpSession session) {
    this.session = session;
  }

  public OAuthConsumerToken getToken(String resourceId) throws AuthenticationException {
    return (OAuthConsumerToken) this.session.getAttribute(KEY_PREFIX + "#" + resourceId);
  }

  public void storeToken(String resourceId, OAuthConsumerToken token) {
    this.session.setAttribute(KEY_PREFIX + "#" + resourceId, token);
  }
}
