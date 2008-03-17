package org.springframework.security.oauth.provider.attributes;

import org.acegisecurity.Authentication;
import org.acegisecurity.ConfigAttribute;
import org.acegisecurity.ConfigAttributeDefinition;
import org.acegisecurity.GrantedAuthority;
import org.acegisecurity.vote.AccessDecisionVoter;
import org.springframework.security.oauth.provider.OAuthAuthenticationDetails;

import java.util.Iterator;

/**
 * @author Ryan Heaton
 */
public class ConsumerSecurityVoter implements AccessDecisionVoter {

  /**
   * The config attribute is supported if it's an instance of {@link org.springframework.security.oauth.provider.attributes.ConsumerSecurityConfig}.
   *
   * @param attribute The attribute.
   * @return Whether the attribute is an instance of {@link org.springframework.security.oauth.provider.attributes.ConsumerSecurityConfig}.
   */
  public boolean supports(ConfigAttribute attribute) {
    return attribute instanceof ConsumerSecurityConfig;
  }

  /**
   * All classes are supported.
   *
   * @param clazz The class.
   * @return true.
   */
  public boolean supports(Class clazz) {
    return true;
  }

  /**
   * Votes on giving access to the specified authentication based on the security attributes.
   *
   * @param authentication The authentication.
   * @param object The object.
   * @param definition The definition.
   * @return The vote.
   */
  public int vote(Authentication authentication, Object object, ConfigAttributeDefinition definition) {
    int result = ACCESS_ABSTAIN;

    if (authentication.getDetails() instanceof OAuthAuthenticationDetails) {
      OAuthAuthenticationDetails details = (OAuthAuthenticationDetails) authentication.getDetails();
      Iterator configAttributes = definition.getConfigAttributes();
      while (configAttributes.hasNext()) {
        ConfigAttribute attribute = (ConfigAttribute) configAttributes.next();

        if (ConsumerSecurityConfig.PERMIT_ALL_ATTRIBUTE.equals(attribute)) {
          return ACCESS_GRANTED;
        }
        else if (ConsumerSecurityConfig.DENY_ALL_ATTRIBUTE.equals(attribute)) {
          return ACCESS_DENIED;
        }
        else if (supports(attribute)) {
          ConsumerSecurityConfig config = (ConsumerSecurityConfig) attribute;
          if ((config.getSecurityType() == ConsumerSecurityConfig.ConsumerSecurityType.CONSUMER_KEY)
            && (config.getAttribute().equals(details.getConsumerDetails().getConsumerKey()))) {
            return ACCESS_GRANTED;
          }
          else if (config.getSecurityType() == ConsumerSecurityConfig.ConsumerSecurityType.CONSUMER_ROLE) {
            GrantedAuthority[] authorities = details.getConsumerDetails().getAuthorities();
            if (authorities != null) {
              for (GrantedAuthority authority : authorities) {
                if (authority.getAuthority().equals(config.getAttribute())) {
                  return ACCESS_GRANTED;
                }
              }
            }
          }
        }
      }
    }

    return result;
  }
}
