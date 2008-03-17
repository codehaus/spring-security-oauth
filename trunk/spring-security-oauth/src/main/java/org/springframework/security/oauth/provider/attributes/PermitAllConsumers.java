package org.springframework.security.oauth.provider.attributes;

import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

/**
 * Annotation used to specify that a method is to be permitted to all OAuth consumers. Note that just because
 * a consumer is permitted, that doesn't mean that the user that the consumer is representing is permitted.
 *
 * @author Ryan Heaton
 */
@Target ( { ElementType.TYPE, ElementType.METHOD } )
@Retention ( RetentionPolicy.RUNTIME )
public @interface PermitAllConsumers {
}