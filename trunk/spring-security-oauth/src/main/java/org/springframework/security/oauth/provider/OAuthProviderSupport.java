package org.springframework.security.oauth.provider;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;

/**
 * Support logic for OAuth providers.
 * 
 * @author Ryan Heaton
 */
public interface OAuthProviderSupport {
  
  /**
   * Parse the oauth consumer paramters from an HttpServletRequest.
   *
   * @param request The servlet request.
   * @return The parsed parameters.
   */
  Map<String, String> parseParameters(HttpServletRequest request);

  /**
   * Get the signature base string for the specified request, per OAuth Core 1.0, 9.1
   *
   * @param request The request.
   * @return The signature base string.
   */
  String getSignatureBaseString(HttpServletRequest request);
}
