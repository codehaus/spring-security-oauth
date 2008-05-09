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

package org.springframework.security.oauth.provider.attributes;

import org.springframework.security.Authentication;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.ConfigAttributeDefinition;
import org.springframework.security.GrantedAuthority;
import org.springframework.security.oauth.provider.OAuthAuthenticationDetails;
import org.springframework.security.vote.AccessDecisionVoter;

import java.util.Collection;

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
      Collection configAttributes = definition.getConfigAttributes();
      for (Object configAttribute : configAttributes) {
        ConfigAttribute attribute = (ConfigAttribute) configAttribute;

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
