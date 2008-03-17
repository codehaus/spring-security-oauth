package org.springframework.security.oauth.consumer.net;

import org.springframework.security.oauth.consumer.ProtectedResourceDetails;
import org.springframework.security.oauth.consumer.OAuthConsumerSupport;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;

import java.net.URLStreamHandler;

/**
 * Default implementation.  Assumes we're running on Sun's JVM.
 *
 * @author Ryan Heaton
 */
public class DefaultOAuthURLStreamHandlerFactory implements OAuthURLStreamHandlerFactory {

  public URLStreamHandler getHttpStreamHandler(ProtectedResourceDetails resourceDetails, OAuthConsumerToken accessToken, OAuthConsumerSupport support) {
    return new OAuthOverHttpURLStreamHandler(resourceDetails, accessToken, support);
  }

  public URLStreamHandler getHttpsStreamHandler(ProtectedResourceDetails resourceDetails, OAuthConsumerToken accessToken, OAuthConsumerSupport support) {
    return new OAuthOverHttpsURLStreamHandler(resourceDetails, accessToken, support);
  }
}
