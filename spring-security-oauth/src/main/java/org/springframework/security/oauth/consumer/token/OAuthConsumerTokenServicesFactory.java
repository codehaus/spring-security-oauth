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

import org.springframework.security.Authentication;

import javax.servlet.http.HttpServletRequest;

/**
 * Factory for token services.
 *
 * @author Ryan Heaton
 */
public interface OAuthConsumerTokenServicesFactory {

  /**
   * Get the token services for the specified request and authentication.
   *
   * @param authentication The authentication.
   * @param request The request
   * @return The token services.
   */
  OAuthConsumerTokenServices getTokenServices(Authentication authentication, HttpServletRequest request);
}
