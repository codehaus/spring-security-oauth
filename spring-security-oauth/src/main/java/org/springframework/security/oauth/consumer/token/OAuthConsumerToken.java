package org.springframework.security.oauth.consumer.token;

import java.io.Serializable;

/**
 * Interface for a consumer-side OAuth token.
 * 
 * @author Ryan Heaton
 */
public class OAuthConsumerToken implements Serializable {

  private String resourceId;
  private String value;
  private String secret;
  private String nonce;
  private boolean accessToken;

  /**
   * The id of the resource to which this token applies.
   *
   * @return The id of the resource to which this token applies.
   */
  public String getResourceId() {
    return resourceId;
  }

  /**
   * The id of the resource to which this token applies.
   *
   * @param resourceId The id of the resource to which this token applies.
   */
  public void setResourceId(String resourceId) {
    this.resourceId = resourceId;
  }

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
   * The nonce associated with this token.
   *
   * @return The nonce associated with this token.
   */
  public String getNonce() {
    return nonce;
  }

  /**
   * The nonce associated with this token.
   *
   * @param nonce The nonce associated with this token.
   */
  public void setNonce(String nonce) {
    this.nonce = nonce;
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
}
