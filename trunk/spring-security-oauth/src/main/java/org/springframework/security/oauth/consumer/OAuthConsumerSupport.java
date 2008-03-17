package org.springframework.security.oauth.consumer;

import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;

import java.net.URL;
import java.io.InputStream;

/**
 * Consumer-side support for OAuth.
 *
 * @author Ryan Heaton
 */
public interface OAuthConsumerSupport {

  /**
   * Get an unauthorized request token for a protected resource.
   *
   * @param resourceId The id of the protected resource for which to get a consumer token.
   * @return The unauthorized request token.
   */
  OAuthConsumerToken getUnauthorizedRequestToken(String resourceId) throws OAuthRequestFailedException;

  /**
   * Get an access token for a protected resource.
   *
   * @param requestToken The (presumably authorized) request token.
   * @return The access token.
   */
  OAuthConsumerToken getAccessToken(OAuthConsumerToken requestToken) throws OAuthRequestFailedException;

  /**
   * Read a protected resource from the given URL using the specified access token.
   *
   * @param url The URL.
   * @param accessToken The access token.
   * @return The protected resource.
   */
  InputStream readProtectedResource(URL url, OAuthConsumerToken accessToken) throws OAuthRequestFailedException;

  /**
   * Configure a URL for protected access.  The result will be a URL that can be used to access
   * the protected resource.
   *
   * @param url The URL.
   * @param accessToken The access token.
   * @return The URL.
   * @throws OAuthRequestFailedException If the protocol for the URL isn't supported. 
   */
  URL configureURLForProtectedAccess(URL url, OAuthConsumerToken accessToken) throws OAuthRequestFailedException;

  /**
   * Get the authorization header using the given access token that should be applied to the specified URL.
   *
   * @param details     The details of the protected resource.
   * @param accessToken The access token.
   * @param url         The URL of the request.
   * @return The authorization header, or null if the authorization header isn't supported by the provider of this resource.
   */
  String getAuthorizationHeader(ProtectedResourceDetails details, OAuthConsumerToken accessToken, URL url);

  /**
   * Get the query string that is to be used in the given request. The query string will
   * include any custom query parameters in the URL and any necessary OAuth parameters.  Note,
   * however, that an OAuth parameter is not considered "necessary" if the provider of the resource
   * supports the authorization header.<br/><br/>
   *
   * The query string is to be used by either applying it to the URL (for HTTP GET) or putting it
   * in the body of the request (for HTTP POST).
   *
   * @param details The resource details.
   * @param accessToken The access token.
   * @param url The URL
   * @return The query string.
   */
  String getOAuthQueryString(ProtectedResourceDetails details, OAuthConsumerToken accessToken, URL url);
}
