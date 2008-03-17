package org.springframework.security.oauth.consumer;

/**
 * Service for loading protected resource details.
 *
 * @author Ryan Heaton
 */
public interface ProtectedResourceDetailsService {

  /**
   * Load the details of a protected resource by id.
   *
   * @param id The id.
   * @return The protected resource details.
   * @throws IllegalArgumentException If there are no details available for the given id.
   */
  ProtectedResourceDetails loadProtectedResourceDetailsById(String id) throws IllegalArgumentException;
}
