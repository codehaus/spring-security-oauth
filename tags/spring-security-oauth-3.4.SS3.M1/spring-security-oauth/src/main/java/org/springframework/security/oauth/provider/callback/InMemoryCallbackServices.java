package org.springframework.security.oauth.provider.callback;

import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthTokenLifecycleListener;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Basic implementation of the callback services that uses an in-memory map.
 *
 * @author Ryan Heaton
 */
public class InMemoryCallbackServices implements OAuthCallbackServices, OAuthTokenLifecycleListener {

  protected final ConcurrentHashMap<String, String> callbackStore = new ConcurrentHashMap<String, String>();

  public void storeCallback(String callback, String requestToken) {
    callbackStore.put(requestToken, callback);
  }

  public String readCallback(String requestToken) {
    return callbackStore.get(requestToken);
  }

  public void tokenCreated(OAuthProviderToken token) {
    //no-op; we don't care.
  }

  public void tokenExpired(OAuthProviderToken token) {
    if (!token.isAccessToken()) {
      callbackStore.remove(token.getValue());
    }
  }

}
