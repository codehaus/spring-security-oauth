package org.springframework.security.oauth.provider.verifier;

/**
 * Service for generating a verifier.
 *
 * @author Ryan Heaton
 */
public interface OAuthVerifierServices {

  /**
   * Create a verifier for the specified request token.
   *
   * @param requestToken The request token.
   * @return The verifier.
   */
  String createVerifier(String requestToken);

  /**
   * Validate the verifier for the specified request token.
   * @param verifier The verifier.
   * @param requestToken the request token.
   * @throws VerificationFailedException If verification failed.
   */
  void validateVerifier(String verifier, String requestToken) throws VerificationFailedException;
}
