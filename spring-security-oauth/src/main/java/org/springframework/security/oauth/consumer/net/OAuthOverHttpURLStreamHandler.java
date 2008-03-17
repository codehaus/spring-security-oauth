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
public class OAuthOverHttpURLStreamHandler extends sun.net.www.protocol.http.Handler {

  private final ProtectedResourceDetails resourceDetails;
  private final OAuthConsumerToken accessToken;
  private final OAuthConsumerSupport support;

  public OAuthOverHttpURLStreamHandler(ProtectedResourceDetails resourceDetails, OAuthConsumerToken accessToken, OAuthConsumerSupport support) {
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
