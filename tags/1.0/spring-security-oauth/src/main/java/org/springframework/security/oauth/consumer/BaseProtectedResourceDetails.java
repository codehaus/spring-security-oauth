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
 * Basic implementation of protected resource details.
 *
 * @author Ryan Heaton
 */
public class BaseProtectedResourceDetails implements ProtectedResourceDetails {

  private String id;
  private String consumerKey;
  private String signatureMethod;
  private SignatureSecret sharedSecret;
  private String requestTokenURL;
  private String userAuthorizationURL;
  private String userAuthorizationTokenParameterName = "oauth_token";
  private String userAuthorizationCallbackParameterName = "oauth_callback";
  private String accessTokenURL;
  private boolean acceptsAuthorizationHeader = true;
  private String authorizationHeaderRealm;

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getConsumerKey() {
    return consumerKey;
  }

  public void setConsumerKey(String consumerKey) {
    this.consumerKey = consumerKey;
  }

  public String getSignatureMethod() {
    return signatureMethod;
  }

  public void setSignatureMethod(String signatureMethod) {
    this.signatureMethod = signatureMethod;
  }

  public SignatureSecret getSharedSecret() {
    return sharedSecret;
  }

  public void setSharedSecret(SignatureSecret sharedSecret) {
    this.sharedSecret = sharedSecret;
  }

  public String getRequestTokenURL() {
    return requestTokenURL;
  }

  public void setRequestTokenURL(String requestTokenURL) {
    this.requestTokenURL = requestTokenURL;
  }

  public String getUserAuthorizationURL() {
    return userAuthorizationURL;
  }

  public void setUserAuthorizationURL(String userAuthorizationURL) {
    this.userAuthorizationURL = userAuthorizationURL;
  }

  public String getUserAuthorizationTokenParameterName() {
    return userAuthorizationTokenParameterName;
  }

  public void setUserAuthorizationTokenParameterName(String userAuthorizationTokenParameterName) {
    this.userAuthorizationTokenParameterName = userAuthorizationTokenParameterName;
  }

  public String getUserAuthorizationCallbackParameterName() {
    return userAuthorizationCallbackParameterName;
  }

  public void setUserAuthorizationCallbackParameterName(String userAuthorizationCallbackParameterName) {
    this.userAuthorizationCallbackParameterName = userAuthorizationCallbackParameterName;
  }

  public String getAccessTokenURL() {
    return accessTokenURL;
  }

  public void setAccessTokenURL(String accessTokenURL) {
    this.accessTokenURL = accessTokenURL;
  }

  public boolean isAcceptsAuthorizationHeader() {
    return acceptsAuthorizationHeader;
  }

  public void setAcceptsAuthorizationHeader(boolean acceptsAuthorizationHeader) {
    this.acceptsAuthorizationHeader = acceptsAuthorizationHeader;
  }

  public String getAuthorizationHeaderRealm() {
    return authorizationHeaderRealm;
  }

  public void setAuthorizationHeaderRealm(String authorizationHeaderRealm) {
    this.authorizationHeaderRealm = authorizationHeaderRealm;
  }
}