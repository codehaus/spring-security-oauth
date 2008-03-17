package org.springframework.security.oauth.consumer;

import java.util.Map;
import java.util.HashMap;

/**
 * Basic, in-memory implementation of a protected resource details service.
 *
 * @author Ryan Heaton
 */
public class InMemoryProtectedResourceDetailsService implements ProtectedResourceDetailsService {

  private Map<String, ProtectedResourceDetails> resourceDetailsStore = new HashMap<String, ProtectedResourceDetails>();

  public ProtectedResourceDetails loadProtectedResourceDetailsById(String id) throws IllegalArgumentException {
    return getResourceDetailsStore().get(id);
  }

  public Map<String, ProtectedResourceDetails> getResourceDetailsStore() {
    return resourceDetailsStore;
  }

  public void setResourceDetailsStore(Map<String, ProtectedResourceDetails> resourceDetailsStore) {
    this.resourceDetailsStore = resourceDetailsStore;
  }
}
