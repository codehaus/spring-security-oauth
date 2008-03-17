package org.springframework.security.oauth.consumer.net;

import org.springframework.security.oauth.consumer.ProtectedResourceDetails;
import org.springframework.security.oauth.consumer.OAuthConsumerSupport;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;

import java.net.URLStreamHandler;

/**
 * Factory for a OAuth URL stream handlers.
 *
 * @author Ryan Heaton
 */
public interface OAuthURLStreamHandlerFactory {

  /**
   * Get the handler for an HTTP stream.
   *
   * @param resourceDetails The resource details.
   * @param accessToken The access token.
   * @param support The logic support.
   * @return The stream handler.
   */
  URLStreamHandler getHttpStreamHandler(ProtectedResourceDetails resourceDetails, OAuthConsumerToken accessToken, OAuthConsumerSupport support);

  /**
   * Get the handler for an HTTPS stream.
   *
   * @param resourceDetails The resource details.
   * @param accessToken The access token.
   * @param support The logic support.
   * @return The stream handler.
   */
  URLStreamHandler getHttpsStreamHandler(ProtectedResourceDetails resourceDetails, OAuthConsumerToken accessToken, OAuthConsumerSupport support);
}
