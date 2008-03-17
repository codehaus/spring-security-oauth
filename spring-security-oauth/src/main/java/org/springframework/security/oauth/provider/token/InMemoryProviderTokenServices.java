package org.springframework.security.oauth.provider.token;

import org.springframework.beans.factory.DisposableBean;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * Implementation of TokenServices that stores tokens in memory. The in-memory token services schedule a task
 * to clean up any expired sessions.
 *
 * @author Ryan Heaton
 */
public class InMemoryProviderTokenServices extends RandomValueProviderTokenServices implements DisposableBean {

  protected final ConcurrentHashMap<String, OAuthProviderTokenImpl> tokenStore = new ConcurrentHashMap<String, OAuthProviderTokenImpl>();
  private ScheduledExecutorService scheduler;
  private Integer cleanupIntervalSeconds;

  @Override
  public void afterPropertiesSet() throws Exception {
    super.afterPropertiesSet();

    if (cleanupIntervalSeconds == null) {
      cleanupIntervalSeconds = 60 * 60;
    }

    if (cleanupIntervalSeconds > 0) {
      scheduler = Executors.newSingleThreadScheduledExecutor();
      Runnable cleanupLogic = new Runnable() {
        public void run() {
          Iterator<Map.Entry<String, OAuthProviderTokenImpl>> entriesIt = tokenStore.entrySet().iterator();
          while (entriesIt.hasNext()) {
            Map.Entry<String, OAuthProviderTokenImpl> entry = entriesIt.next();
            if (isExpired(entry.getValue())) {
              //there's a race condition here, but we'll live with it for now.
              entriesIt.remove();
            }
          }
        }
      };
      scheduler.scheduleAtFixedRate(cleanupLogic, getAccessTokenValiditySeconds(), cleanupIntervalSeconds, TimeUnit.SECONDS);
    }
  }

  public void destroy() throws Exception {
    if (scheduler != null) {
      scheduler.shutdownNow();
    }
  }

  protected OAuthProviderTokenImpl readToken(String token) {
    return tokenStore.get(token);
  }

  protected void storeToken(String tokenValue, OAuthProviderTokenImpl token) {
    tokenStore.put(tokenValue, token);
  }

  protected void removeToken(String tokenValue) {
    tokenStore.remove(tokenValue);
  }

  /**
   * The interval at which to schedule cleanup. (&lt;= 0 for never).
   *
   * @return The interval at which to schedule cleanup.
   */
  public Integer getCleanupIntervalSeconds() {
    return cleanupIntervalSeconds;
  }

  /**
   * The interval at which to schedule cleanup.
   *
   * @param cleanupIntervalSeconds The interval at which to schedule cleanup.
   */
  public void setCleanupIntervalSeconds(Integer cleanupIntervalSeconds) {
    this.cleanupIntervalSeconds = cleanupIntervalSeconds;
  }
}
