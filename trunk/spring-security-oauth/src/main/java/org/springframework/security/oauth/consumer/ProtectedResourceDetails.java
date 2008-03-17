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
   * The URL to use to obtain an OAuth access token.
   *
   * @return The URL to use to obtain an OAuth access token.
   */
  String getAccessTokenURL();

  /**
   * The HTTP method to use for interfacing with the provider. (Default is "POST").
   *
   * @return The HTTP method to use for interfacing with the provider.
   */
  String getHTTPMethod();

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
