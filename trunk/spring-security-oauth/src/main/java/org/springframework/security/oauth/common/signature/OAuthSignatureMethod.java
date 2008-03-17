package org.springframework.security.oauth.common.signature;

/**
 * @author Ryan Heaton
 */
public interface OAuthSignatureMethod {

  /**
   * The name of the OAuth signature method.
   *
   * @return The name of the OAuth signature method.
   */
  String getName();

  /**
   * Sign the signature base string.
   *
   * @param signatureBaseString The signature base string to sign.
   * @return The signature.
   */
  String sign(String signatureBaseString);

  /**
   * Verify the specified signature on the given signature base string.
   *
   * @param signatureBaseString The signature base string.
   * @param signature The signature.
   */
  void verify(String signatureBaseString, String signature) throws InvalidSignatureException;
  
}
