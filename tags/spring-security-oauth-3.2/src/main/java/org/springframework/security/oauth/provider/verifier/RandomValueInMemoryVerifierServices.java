package org.springframework.security.oauth.provider.verifier;

import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.provider.token.OAuthTokenLifecycleListener;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.beans.factory.InitializingBean;

import java.util.concurrent.ConcurrentHashMap;
import java.util.Random;
import java.security.SecureRandom;

/**
 * Basic implementation of the verifier services that creates a random-value verifier and stores it in an in-memory map.
 *
 * @author Ryan Heaton
 */
public class RandomValueInMemoryVerifierServices implements OAuthVerifierServices, OAuthTokenLifecycleListener, InitializingBean {

  protected final ConcurrentHashMap<String, String> verifierStore = new ConcurrentHashMap<String, String>();
  private static final char[] DEFAULT_CODEC = "1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz".toCharArray();

  private Random random;
  private int verifierLengthBytes = 6;

  public void afterPropertiesSet() throws Exception {
    if (getRandom() == null) {
      setRandom(new SecureRandom());
    }
  }

  public String createVerifier(String requestToken) {
    byte[] verifierBytes = new byte[getVerifierLengthBytes()];
    getRandom().nextBytes(verifierBytes);
    String verifier = getVerifierString(verifierBytes);
    this.verifierStore.put(requestToken, verifier);
    return verifier;
  }

  /**
   * Convert these random bytes to a verifier string. The length of the byte array can be {@link #setVerifierLengthBytes(int) configured}. Default implementation
   * mods the bytes to fit into the ASCII letters 1-9, A-Z, a-z .
   * 
   * @param verifierBytes The bytes.
   * @return The string.
   */
  protected String getVerifierString(byte[] verifierBytes) {
    char[] chars = new char[verifierBytes.length];
    for (int i = 0; i < verifierBytes.length; i++) {
      chars[i] = DEFAULT_CODEC[((verifierBytes[i] & 0xFF) % DEFAULT_CODEC.length)];
    }
    return new String(chars);
  }

  public void validateVerifier(String verifier, String requestToken) throws VerificationFailedException {
    if (!verifier.equals(this.verifierStore.get(requestToken))) {
      throw new VerificationFailedException("Incorrect OAuth verifier " + verifier + " for request token " + requestToken + ".");
    }
  }

  public void tokenCreated(OAuthProviderToken token) {
    //no-op; we don't care.
  }

  public void tokenExpired(OAuthProviderToken token) {
    if (!token.isAccessToken()) {
      verifierStore.remove(token.getValue());
    }
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
   * The verifier length in bytes, before being encoded to a string.
   *
   * @return The verifier length in bytes, before being encoded to a string.
   */
  public int getVerifierLengthBytes() {
    return verifierLengthBytes;
  }

  /**
   * The verifier length in bytes, before being encoded to a string.
   *
   * @param verifierLengthBytes The verifier length in bytes, before being encoded to a string.
   */
  public void setVerifierLengthBytes(int verifierLengthBytes) {
    this.verifierLengthBytes = verifierLengthBytes;
  }
}