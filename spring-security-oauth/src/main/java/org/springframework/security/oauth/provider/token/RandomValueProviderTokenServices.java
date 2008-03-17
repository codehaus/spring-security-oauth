package org.springframework.security.oauth.provider.token;

import org.acegisecurity.*;
import org.springframework.beans.factory.InitializingBean;
import org.apache.commons.codec.binary.Base64;

import java.util.Random;
import java.util.UUID;
import java.security.SecureRandom;

/**
 * Base implementation for token services that uses random values to generate tokens. Only the persistence mechanism
 * is left unimplemented.<br/><br/>
 *
 * This base implementation creates tokens that have an expiration.  For request tokens, the default validity is
 * 10 minutes.  For access tokens, the default validity is 12 hours.<br/><br/>
 *
 *
 * @author Ryan Heaton
 */
public abstract class RandomValueProviderTokenServices implements OAuthProviderTokenServices, InitializingBean {

  private Random random;
  private int requestTokenValiditySeconds = 60 * 10; //default 10 minutes.
  private int accessTokenValiditySeconds = 60 * 60 * 12; //default 12 hours.
  private int tokenSecretLengthBytes = 80;

  /**
   * Read a token from persistence.
   *
   * @param token The token to read.
   * @return The token, or null if the token doesn't exist.
   */
  protected abstract OAuthProviderTokenImpl readToken(String token);

  /**
   * Store a token from persistence.
   *
   * @param tokenValue The token value.
   * @param token The token to store.
   */
  protected abstract void storeToken(String tokenValue, OAuthProviderTokenImpl token);

  /**
   * Remove a token from persistence.
   *
   * @param tokenValue The token to remove.
   */
  protected abstract void removeToken(String tokenValue);

  /**
   * Initialze these token services. If no random generator is set, one will be created.
   *
   * @throws Exception
   */
  public void afterPropertiesSet() throws Exception {
    if (random == null) {
      random = new SecureRandom();
    }
  }

  public OAuthProviderToken getToken(String token) throws AuthenticationException {
    OAuthProviderTokenImpl authToken = readToken(token);
    
    if (authToken == null) {
      throw new InvalidOAuthTokenException("Invalid token: " + token);
    }

    if (isExpired(authToken)) {
      throw new ExpiredOAuthTokenException("Expired token.");
    }

    return authToken;
  }

  /**
   * Whether the auth token is expired.
   *
   * @param authToken The auth token to check for expiration.
   * @return Whether the auth token is expired. 
   */
  protected boolean isExpired(OAuthProviderTokenImpl authToken) {
    if (authToken.isAccessToken()) {
      if ((authToken.getTimestamp() + (getAccessTokenValiditySeconds() * 1000)) < System.currentTimeMillis()) {
        return true;
      }
    }
    else {
      if ((authToken.getTimestamp() + (getRequestTokenValiditySeconds() * 1000)) < System.currentTimeMillis()) {
        return true;
      }
    }

    return false;
  }

  public OAuthProviderToken createUnauthorizedRequestToken(String consumerKey) throws AuthenticationException {
    String tokenValue = UUID.randomUUID().toString();
    byte[] secretBytes = new byte[getTokenSecretLengthBytes()];
    getRandom().nextBytes(secretBytes);
    String secret = new String(Base64.encodeBase64(secretBytes));
    OAuthProviderTokenImpl token = new OAuthProviderTokenImpl();
    token.setAccessToken(false);
    token.setConsumerKey(consumerKey);
    token.setUserAuthentication(null);
    token.setSecret(secret);
    token.setValue(tokenValue);
    token.setTimestamp(System.currentTimeMillis());
    storeToken(tokenValue, token);
    return token;
  }

  public void authorizeRequestToken(String requestToken, Authentication authentication) throws AuthenticationException {
    OAuthProviderTokenImpl authToken = readToken(requestToken);
    if (authToken.isAccessToken()) {
      throw new InvalidOAuthTokenException("Request to authorize an access token.");
    }

    authToken.setUserAuthentication(authentication);
    authToken.setTimestamp(System.currentTimeMillis());//reset the expiration.
    storeToken(requestToken, authToken);
  }

  public OAuthAccessProviderToken createAccessToken(String requestToken) throws AuthenticationException {
    OAuthProviderTokenImpl authToken = readToken(requestToken);
    if (authToken.isAccessToken()) {
      throw new InvalidOAuthTokenException("Not a request token.");
    }
    else if (authToken.getUserAuthentication() == null) {
      throw new InvalidOAuthTokenException("Request token has not been authorized.");
    }

    removeToken(requestToken);

    String tokenValue = UUID.randomUUID().toString();
    byte[] secretBytes = new byte[getTokenSecretLengthBytes()];
    getRandom().nextBytes(secretBytes);
    String secret = new String(Base64.encodeBase64(secretBytes));
    OAuthProviderTokenImpl token = new OAuthProviderTokenImpl();
    token.setAccessToken(true);
    token.setConsumerKey(authToken.getConsumerKey());
    token.setUserAuthentication(authToken.getUserAuthentication());
    token.setSecret(secret);
    token.setValue(tokenValue);
    token.setTimestamp(System.currentTimeMillis());
    storeToken(tokenValue, token);
    return token;
  }

  /**
   * The length of the token secret in bytes, before being base64-encoded.
   *
   * @return The length of the token secret in bytes.
   */
  public int getTokenSecretLengthBytes() {
    return tokenSecretLengthBytes;
  }

  /**
   * The length of the token secret in bytes, before being base64-encoded.
   *
   * @param tokenSecretLengthBytes The length of the token secret in bytes, before being base64-encoded.
   */
  public void setTokenSecretLengthBytes(int tokenSecretLengthBytes) {
    this.tokenSecretLengthBytes = tokenSecretLengthBytes;
  }

  /**
   * The random value generator used to create token secrets.
   *
   * @return The random value generator used to create token secrets.
   */
  public Random getRandom() {
    return random;
  }

  /**
   * The random value generator used to create token secrets.
   *
   * @param random The random value generator used to create token secrets.
   */
  public void setRandom(Random random) {
    this.random = random;
  }

  /**
   * The validity (in seconds) of the unauthenticated request token.
   *
   * @return The validity (in seconds) of the unauthenticated request token.
   */
  public int getRequestTokenValiditySeconds() {
    return requestTokenValiditySeconds;
  }

  /**
   * The validity (in seconds) of the unauthenticated request token.
   *
   * @param requestTokenValiditySeconds The validity (in seconds) of the unauthenticated request token.
   */
  public void setRequestTokenValiditySeconds(int requestTokenValiditySeconds) {
    this.requestTokenValiditySeconds = requestTokenValiditySeconds;
  }

  /**
   * The validity (in seconds) of the access token.
   *
   * @return The validity (in seconds) of the access token.
   */
  public int getAccessTokenValiditySeconds() {
    return accessTokenValiditySeconds;
  }

  /**
   * The validity (in seconds) of the access token.
   *
   * @param accessTokenValiditySeconds The validity (in seconds) of the access token.
   */
  public void setAccessTokenValiditySeconds(int accessTokenValiditySeconds) {
    this.accessTokenValiditySeconds = accessTokenValiditySeconds;
  }

}
