package org.springframework.security.oauth.provider.token;

import org.acegisecurity.Authentication;

/**
 * Basic implementation for an OAuth token.
 *
 * @author Ryan Heaton
 */
public class OAuthProviderTokenImpl implements OAuthAccessProviderToken {

  private String value;
  private String secret;
  private String consumerKey;
  private boolean accessToken;
  private Authentication userAuthentication;
  private long timestamp;

  /**
   * The value of the token.
   *
   * @return The value of the token.
   */
  public String getValue() {
    return value;
  }

  /**
   * The value of the token.
   *
   * @param value The value of the token.
   */
  public void setValue(String value) {
    this.value = value;
  }

  /**
   * The token secret.
   *
   * @return The token secret.
   */
  public String getSecret() {
    return secret;
  }

  /**
   * The token secret.
   *
   * @param secret The token secret.
   */
  public void setSecret(String secret) {
    this.secret = secret;
  }

  /**
   * The consumer key associated with this oauth token.
   *
   * @return The consumer key associated with this oauth token.
   */
  public String getConsumerKey() {
    return consumerKey;
  }

  /**
   * The consumer key associated with this oauth token.
   *
   * @param consumerKey The consumer key associated with this oauth token.
   */
  public void setConsumerKey(String consumerKey) {
    this.consumerKey = consumerKey;
  }

  /**
   * Whether this is an OAuth access token.
   *
   * @return Whether this is an OAuth access token.
   */
  public boolean isAccessToken() {
    return accessToken;
  }

  /**
   * Whether this is an OAuth access token.
   *
   * @param accessToken Whether this is an OAuth access token.
   */
  public void setAccessToken(boolean accessToken) {
    this.accessToken = accessToken;
  }

  /**
   * The authentication of the user who granted the access token.
   *
   * @return The authentication of the user who granted the access token.
   */
  public Authentication getUserAuthentication() {
    return userAuthentication;
  }

  /**
   * The authentication of the user who granted the access token.
   *
   * @param userAuthentication The authentication of the user who granted the access token.
   */
  public void setUserAuthentication(Authentication userAuthentication) {
    this.userAuthentication = userAuthentication;
  }

  /**
   * Timestamp associated with this token.
   *
   * @return Timestamp associated with this token.
   */
  public long getTimestamp() {
    return timestamp;
  }

  /**
   * Timestamp associated with this token.
   *
   * @param timestamp Timestamp associated with this token.
   */
  public void setTimestamp(long timestamp) {
    this.timestamp = timestamp;
  }

}
