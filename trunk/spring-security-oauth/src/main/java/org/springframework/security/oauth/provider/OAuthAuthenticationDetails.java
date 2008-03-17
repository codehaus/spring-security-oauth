package org.springframework.security.oauth.provider;

import org.acegisecurity.ui.WebAuthenticationDetails;

import javax.servlet.http.HttpServletRequest;

/**
 * Authentication details and includes the details of the OAuth consumer.
 * 
 * @author Ryan Heaton
 */
public class OAuthAuthenticationDetails extends WebAuthenticationDetails {

  private final ConsumerDetails consumerDetails;

  public OAuthAuthenticationDetails(HttpServletRequest request, ConsumerDetails consumerDetails) {
    super(request);
    this.consumerDetails = consumerDetails;
  }

  public ConsumerDetails getConsumerDetails() {
    return consumerDetails;
  }
}
