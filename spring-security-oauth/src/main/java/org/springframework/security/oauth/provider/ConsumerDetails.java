package org.springframework.security.oauth.provider;

import org.springframework.security.oauth.common.signature.SignatureSecret;
import org.acegisecurity.GrantedAuthority;

import java.io.Serializable;

/**
 * Provides core OAuth consumer information.
 *
 * @author Ryan Heaton
 */
public interface ConsumerDetails extends Serializable {

  /**
   * The consumer key.
   *
   * @return The consumer key.
   */
  String getConsumerKey();

  /**
   * The name of the consumer (for display purposes).
   *
   * @return The name of the consumer (for display purposes).
   */
  String getConsumerName();

  /**
   * The signature secret.
   *
   * @return The signature secret.
   */
  SignatureSecret getSignatureSecret();

  /**
   * Get the authorities that are granted to the OAuth consumer.  Not the these are NOT the authorities
   * that are granted to the consumer with a user-authorized access token. Instead, these authorities are
   * inherent to the consumer itself.
   *
   * @return The authorities.
   */
  GrantedAuthority[] getAuthorities();
}
