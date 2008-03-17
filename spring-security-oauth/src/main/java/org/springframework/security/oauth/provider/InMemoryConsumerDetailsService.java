package org.springframework.security.oauth.provider;

import org.springframework.security.oauth.common.OAuthException;

import java.util.HashMap;
import java.util.Map;

/**
 * Basic, in-memory implementation of the consumer details service.
 *
 * @author Ryan Heaton
 */
public class InMemoryConsumerDetailsService implements ConsumerDetailsService {

  private Map<String, ConsumerDetails> consumerDetailsStore = new HashMap<String, ConsumerDetails>();

  public ConsumerDetails loadConsumerByConsumerKey(String consumerKey) throws OAuthException {
    ConsumerDetails details = consumerDetailsStore.get(consumerKey);
    if (details == null) {
      throw new InvalidOAuthParametersException("Consumer not found: " + consumerKey);
    }
    return details;
  }

  public Map<String, ConsumerDetails> getConsumerDetailsStore() {
    return consumerDetailsStore;
  }

  public void setConsumerDetailsStore(Map<String, ConsumerDetails> consumerDetailsStore) {
    this.consumerDetailsStore = consumerDetailsStore;
  }
}
