package org.springframework.security.oauth.provider;

import org.springframework.security.oauth.common.OAuthException;

/**
 * A service that provides the details about an oauth consumer.
 *
 * @author Ryan Heaton
 */
public interface ConsumerDetailsService {

  /**
   * Load a consumer by the consumer key. This method must NOT return null.
   *
   * @param consumerKey The consumer key.
   * @return The consumer details.
   * @throws OAuthException If the consumer account is locked, expired, disabled, or for any other reason.
   */
  ConsumerDetails loadConsumerByConsumerKey(String consumerKey) throws OAuthException;

}
