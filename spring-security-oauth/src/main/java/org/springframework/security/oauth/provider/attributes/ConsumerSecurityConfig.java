package org.springframework.security.oauth.provider.attributes;

import org.acegisecurity.SecurityConfig;

/**
 * Security config for consumer authorization of a method.
 * 
 * @author Ryan Heaton
 */
public class ConsumerSecurityConfig extends SecurityConfig {

  public static final ConsumerSecurityConfig DENY_ALL_ATTRIBUTE = new ConsumerSecurityConfig(DenyAllConsumers.class.getName(), null);
  public static final ConsumerSecurityConfig PERMIT_ALL_ATTRIBUTE = new ConsumerSecurityConfig(PermitAllConsumers.class.getName(), null);

  /**
   * Type of security.
   */
  public enum ConsumerSecurityType {

    /**
     * Consumer key type.
     */
    CONSUMER_KEY,

    /**
     * Consumer role type.
     */
    CONSUMER_ROLE

  }

  private final ConsumerSecurityType securityType;

  public ConsumerSecurityConfig(String config, ConsumerSecurityType type) {
    super(config);
    this.securityType = type;
  }

  public ConsumerSecurityType getSecurityType() {
    return securityType;
  }
}
