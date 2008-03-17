package org.springframework.security.oauth.provider.attributes;

import java.lang.annotation.Target;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;

/**
 * The consumer keys that are allowed to access the specified method.
 *
 * @author Ryan Heaton
 */
@Target ( { ElementType.TYPE, ElementType.METHOD } )
@Retention ( RetentionPolicy.RUNTIME )
public @interface ConsumerKeysAllowed {

  String[] value();
  
}
