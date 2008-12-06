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

package org.springframework.security.oauth.provider;

import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.providers.AbstractAuthenticationToken;

/**
 * Authentication for an OAuth consumer.
 * 
 * @author Ryan Heaton
 */
public class ConsumerAuthentication extends AbstractAuthenticationToken {

  private final ConsumerDetails consumerDetails;
  private final ConsumerCredentials consumerCredentials;
  private boolean signatureValidated = false;

  public ConsumerAuthentication(ConsumerDetails consumerDetails, ConsumerCredentials consumerCredentials) {
    this.consumerDetails = consumerDetails;
    this.consumerCredentials = consumerCredentials;
  }

  /**
   * The authorities of the consumer (these do not include the authorities granted to the consumer with
   * an authorized request token).
   *
   * @return The authorities of the consumer.
   */
  @Override
  public GrantedAuthority[] getAuthorities() {
    return getConsumerDetails().getAuthorities();
  }

  /**
   * The credentials.
   *
   * @return The credentials.
   * @see #getConsumerCredentials()
   */
  public Object getCredentials() {
    return getConsumerCredentials();
  }

  /**
   * The credentials of this authentication.
   *
   * @return The credentials of this authentication.
   */
  public ConsumerCredentials getConsumerCredentials() {
    return consumerCredentials;
  }

  /**
   * The principal ({@link #getConsumerDetails() consumer details}).
   *
   * @return The principal.
   * @see #getConsumerDetails()
   */
  public Object getPrincipal() {
    return getConsumerDetails();
  }

  /**
   * The consumer details.
   *
   * @return The consumer details.
   */
  public ConsumerDetails getConsumerDetails() {
    return consumerDetails;
  }

  /**
   * The name of this principal is the consumer key.
   *
   * @return The name of this principal is the consumer key.
   */
  public String getName() {
    return getConsumerDetails() != null ? getConsumerDetails().getConsumerKey() : null;
  }

  /**
   * Whether the signature has been validated.
   *
   * @return Whether the signature has been validated.
   */
  public boolean isSignatureValidated() {
    return signatureValidated;
  }

  /**
   * Whether the signature has been validated.
   *
   * @param signatureValidated Whether the signature has been validated.
   */
  public void setSignatureValidated(boolean signatureValidated) {
    this.signatureValidated = signatureValidated;
  }

  /**
   * Whether the signature has been validated.
   *
   * @return Whether the signature has been validated.
   */
  @Override
  public boolean isAuthenticated() {
    return isSignatureValidated();
  }

  /**
   * Whether the signature has been validated.
   *
   * @param authenticated Whether the signature has been validated.
   */
  @Override
  public void setAuthenticated(boolean authenticated) {
    setSignatureValidated(authenticated);
  }

}