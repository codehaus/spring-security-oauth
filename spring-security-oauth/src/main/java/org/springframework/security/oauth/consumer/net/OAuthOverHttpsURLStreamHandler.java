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

package org.springframework.security.oauth.consumer.net;

import org.springframework.security.oauth.consumer.ProtectedResourceDetails;
import org.springframework.security.oauth.consumer.OAuthConsumerSupport;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;

import java.io.IOException;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;

/**
 * Stream handler to handle the request stream to a protected resource over HTTP.
 *
 * @author Ryan Heaton
 */
public class OAuthOverHttpsURLStreamHandler extends sun.net.www.protocol.https.Handler {

  private final ProtectedResourceDetails resourceDetails;
  private final OAuthConsumerToken accessToken;
  private final OAuthConsumerSupport support;

  public OAuthOverHttpsURLStreamHandler(ProtectedResourceDetails resourceDetails, OAuthConsumerToken accessToken, OAuthConsumerSupport support) {
    this.resourceDetails = resourceDetails;
    this.accessToken = accessToken;
    this.support = support;
  }

  @Override
  protected URLConnection openConnection(URL url) throws IOException {
    URLConnection connection = super.openConnection(url);
    if (resourceDetails.isAcceptsAuthorizationHeader()) {
      String authHeader = support.getAuthorizationHeader(resourceDetails, accessToken, url);
      connection.setRequestProperty("Authorization", authHeader);
    }
    return connection;
  }

  @Override
  protected URLConnection openConnection(URL url, Proxy proxy) throws IOException {
    URLConnection connection = super.openConnection(url, proxy);
    if (resourceDetails.isAcceptsAuthorizationHeader()) {
      String authHeader = support.getAuthorizationHeader(resourceDetails, accessToken, url);
      connection.setRequestProperty("Authorization", authHeader);
    }
    return connection;
  }

}