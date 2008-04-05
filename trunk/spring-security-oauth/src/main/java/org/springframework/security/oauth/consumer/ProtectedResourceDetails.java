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

package org.springframework.security.oauth.consumer;

import org.springframework.security.oauth.common.signature.SignatureSecret;

/**
 * Details about a protected resource.
 *
 * @author Ryan Heaton
 */
public interface ProtectedResourceDetails {

  /**
   * An identifier for these resource details.
   *
   * @return An identifier for these resource details.
   */
  String getId();

  /**
   * The consumer key with which to interact with the provider.
   *
   * @return The consumer key with which to interact with the provider.
   */
  String getConsumerKey();

  /**
   * The signature method to use for OAuth requests.
   *
   * @return The signature method to use for OAuth requests.
   */
  String getSignatureMethod();

  /**
   * The shared signature secret.
   *
   * @return The shared signature secret.
   */
  SignatureSecret getSharedSecret();

  /**
   * The URL to use to obtain an OAuth request token.
   *
   * @return The URL to use to obtain an OAuth request token.
   */
  String getRequestTokenURL();

  /**
   * The URL to which to redirect the user for authorization of access to the protected resource.
   *
   * @return The URL to which to redirect the user for authorization of access to the protected resource.
   */
  String getUserAuthorizationURL();

  /**
   * The parameter name of the request token parameter at the user authorization URL.
   *
   * @return The parameter name of the request token parameter at the user authorization URL.
   */
  String getUserAuthorizationTokenParameterName();

  /**
   * The parameter name of the callback parameter at the user authorization URL.
   *
   * @return The parameter name of the the callback parameter at the user authorization URL.
   */
  String getUserAuthorizationCallbackParameterName();

  /**
   * The URL to use to obtain an OAuth access token.
   *
   * @return The URL to use to obtain an OAuth access token.
   */
  String getAccessTokenURL();

  /**
   * Whether the provider of this resource accepts the OAuth Authorization HTTP header.  Default: true.
   *
   * @return Whether the provider of this resource accepts the OAuth Authorization HTTP header.
   */
  boolean isAcceptsAuthorizationHeader();

  /**
   * The value of the realm of the authorization header, or null if none.
   *
   * @return The value of the realm of the authorization header
   */
  String getAuthorizationHeaderRealm();

}
