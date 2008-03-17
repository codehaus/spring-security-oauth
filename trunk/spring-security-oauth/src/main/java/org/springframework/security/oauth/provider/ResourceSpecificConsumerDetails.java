package org.springframework.security.oauth.provider;

/**
 * Consumer details for a specific resource.
 *
 * @author Ryan Heaton
 */
public interface ResourceSpecificConsumerDetails extends ConsumerDetails {

  /**
   * The name of the resource.
   *
   * @return The name of the resource.
   */
  String getResourceName();

  /**
   * A description of the resource.
   *
   * @return A description of the resource.
   */
  String getResourceDescription();
}
