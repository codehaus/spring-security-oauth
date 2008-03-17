package org.springframework.security.oauth.common;

/**
 * Enumeration for consumer parameters.
 *
 * @author Ryan Heaton
 */
public enum OAuthConsumerParameter {

  /**
   * Parameter for the consumer key.
   */
  oauth_consumer_key,

  /**
   * Parameter for the oauth token.
   */
  oauth_token,

  /**
   * Parameter for the signature method.
   */
  oauth_signature_method,

  /**
   * Parameter for the signature.
   */
  oauth_signature,

  /**
   * Parameter for the timestamp.
   */
  oauth_timestamp,

  /**
   * Parameter for the nonce.
   */
  oauth_nonce,

  /**
   * Parameter for the version.
   */
  oauth_version,

}
