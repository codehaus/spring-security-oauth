package org.springframework.security.oauth.provider.attributes;

import org.acegisecurity.SecurityConfig;

import java.util.Collection;
import java.util.Collections;
import java.util.ArrayList;
import java.lang.reflect.Method;
import java.lang.reflect.Field;

/**
 * @author Ryan Heaton
 */
public class ConsumerSecurityAnnotationAttributes implements org.springframework.metadata.Attributes {
  // Inherited.
  public Collection getAttributes(Class targetClass) {
    return Collections.emptyList();
  }

  // Inherited.
  public Collection getAttributes(Class targetClass, Class filter) {
    throw new UnsupportedOperationException();
  }

  // Inherited.
  public Collection getAttributes(Method targetMethod) {
    ArrayList<SecurityConfig> attributes = new ArrayList<SecurityConfig>();

    //todo: throw an exception if two or more of @DenyAll, @PermitAll, and @RolesAllowed are present (illegal according to JSR250)?

    DenyAllConsumers denyAll = targetMethod.getAnnotation(DenyAllConsumers.class);
    if (denyAll != null) {
      attributes.add(ConsumerSecurityConfig.DENY_ALL_ATTRIBUTE);
    }
    else {
      PermitAllConsumers permitAll = targetMethod.getAnnotation(PermitAllConsumers.class);
      if (permitAll != null) {
        attributes.add(ConsumerSecurityConfig.PERMIT_ALL_ATTRIBUTE);
      }
      else {
        ConsumerRolesAllowed rolesAllowed = targetMethod.getAnnotation(ConsumerRolesAllowed.class);
        if (rolesAllowed != null) {
          for (String role : rolesAllowed.value()) {
            attributes.add(new ConsumerSecurityConfig(role, ConsumerSecurityConfig.ConsumerSecurityType.CONSUMER_ROLE));
          }
        }
        else {
          ConsumerKeysAllowed keysAllowed = targetMethod.getAnnotation(ConsumerKeysAllowed.class);
          if (keysAllowed != null) {
            for (String key : keysAllowed.value()) {
              attributes.add(new ConsumerSecurityConfig(key, ConsumerSecurityConfig.ConsumerSecurityType.CONSUMER_KEY));
            }
          }
          else {
            //now check the class-level attributes:
            denyAll = targetMethod.getDeclaringClass().getAnnotation(DenyAllConsumers.class);
            if (denyAll != null) {
              attributes.add(ConsumerSecurityConfig.DENY_ALL_ATTRIBUTE);
            }
            else {
              permitAll = targetMethod.getDeclaringClass().getAnnotation(PermitAllConsumers.class);
              if (permitAll != null) {
                attributes.add(ConsumerSecurityConfig.PERMIT_ALL_ATTRIBUTE);
              }
              else {
                rolesAllowed = targetMethod.getDeclaringClass().getAnnotation(ConsumerRolesAllowed.class);
                if (rolesAllowed != null) {
                  for (String role : rolesAllowed.value()) {
                    attributes.add(new ConsumerSecurityConfig(role, ConsumerSecurityConfig.ConsumerSecurityType.CONSUMER_ROLE));
                  }
                }
                else {
                  keysAllowed = targetMethod.getDeclaringClass().getAnnotation(ConsumerKeysAllowed.class);
                  if (keysAllowed != null) {
                    for (String key : keysAllowed.value()) {
                      attributes.add(new ConsumerSecurityConfig(key, ConsumerSecurityConfig.ConsumerSecurityType.CONSUMER_KEY));
                    }
                  }
                }
              }
            }
          }
        }
      }
    }

    return attributes;
  }

  // Inherited.
  public Collection getAttributes(Method targetMethod, Class filter) {
    throw new UnsupportedOperationException();
  }

  // Inherited.
  public Collection getAttributes(Field targetField) {
    throw new UnsupportedOperationException();
  }

  // Inherited.
  public Collection getAttributes(Field targetField, Class filter) {
    throw new UnsupportedOperationException();
  }

}
