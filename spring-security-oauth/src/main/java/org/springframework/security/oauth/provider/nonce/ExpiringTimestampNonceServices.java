package org.springframework.security.oauth.provider.nonce;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.CredentialsExpiredException;
import org.springframework.security.oauth.provider.ConsumerDetailsService;
import org.springframework.security.oauth.provider.ConsumerDetails;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * Nonce services that only validates the timestamp of a consumer request.  The nonce
 * is not checked for replay attacks.<br/><br/>
 *
 * The timestamp is interpreted as the number of seconds from January 1, 1970 00:00:00 GMT.  If the timestamp
 * is older than the configured validity window, the nonce is not valid. The default validity window is
 * 12 hours.
 *
 * @author Ryan Heaton
 */
public class ExpiringTimestampNonceServices implements OAuthNonceServices, InitializingBean {

  private long validityWindowSeconds = 60 * 60 * 12; //we'll default to a 12-hour validity window.
  private ConsumerDetailsService consumerDetailsService;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(consumerDetailsService, "A consumer details service must be supplied to validate the consumer key.");
  }

  public boolean validateNonce(ConsumerDetails consumerDetails, long timestamp, String nonce) throws AuthenticationException {
    long nowSeconds = (System.currentTimeMillis() / 1000);
    if ((nowSeconds - timestamp) > getValidityWindowSeconds()) {
      throw new CredentialsExpiredException("Expired timestamp.");
    }

    //just assume it's not a new timestamp.
    return false;
  }

  /**
   * The consumer details service.
   *
   * @return The consumer details service.
   */
  public ConsumerDetailsService getConsumerDetailsService() {
    return consumerDetailsService;
  }

  /**
   * The consumer details service.
   *
   * @param consumerDetailsService The consumer details service.
   */
  public void setConsumerDetailsService(ConsumerDetailsService consumerDetailsService) {
    this.consumerDetailsService = consumerDetailsService;
  }

  /**
   * Set the timestamp validity window (in seconds).
   *
   * @return the timestamp validity window (in seconds).
   */
  public long getValidityWindowSeconds() {
    return validityWindowSeconds;
  }

  /**
   * The timestamp validity window (in seconds).
   *
   * @param validityWindowSeconds the timestamp validity window (in seconds).
   */
  public void setValidityWindowSeconds(long validityWindowSeconds) {
    this.validityWindowSeconds = validityWindowSeconds;
  }
}
