package org.springframework.security.oauth2.provider;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Collection;
import java.util.Set;
import java.util.TreeSet;

/**
 * @author Ryan Heaton
 */
public class ClientAuthenticationToken extends AbstractAuthenticationToken {

  private final String clientId;
  private final String clientSecret;
  private final String flowType;
  private final Set<String> scope;
  private final HttpServletRequest request;

  /**
   * Construct an unauthenticated Client Authentication from a request and a specific authorization type.
   *
   * @param request The request.
   * @param flowType The authorization type.
   */
  public ClientAuthenticationToken(HttpServletRequest request, String flowType) {
    super(null);
    this.clientId = request.getParameter("client_id");
    this.clientSecret = request.getParameter("client_secret");

    Set<String> scope = new TreeSet<String>();
    String scopeValue = request.getParameter("scope");
    if (scopeValue != null) {
      //the spec says the scope is separated by spaces, but Facebook uses commas, so we'll include commas, too.
      String[] tokens = scopeValue.split("[\\s+,]");
      scope.addAll(Arrays.asList(tokens));
    }
    this.scope = scope;
    this.flowType = flowType;
    this.request = request;
  }

  /**
   * Construct an <em>authenticated</em> token from an unauthenticated token.
   *
   * @param unauthenticated The unauthenticated token.
   * @param authorities The authorities granted.
   */
  public ClientAuthenticationToken(ClientAuthenticationToken unauthenticated, Collection<GrantedAuthority> authorities) {
    super(authorities);
    this.clientId = unauthenticated.getClientId();
    this.clientSecret = unauthenticated.getClientSecret();
    this.scope = unauthenticated.getScope();
    this.flowType = unauthenticated.getFlowType();
    this.request = unauthenticated.getRequest();
    setAuthenticated(true);
  }

  public String getClientId() {
    return this.clientId;
  }

  public Object getPrincipal() {
    return getClientId();
  }

  public String getClientSecret() {
    return this.clientSecret;
  }

  public Object getCredentials() {
    return getClientSecret();
  }

  public Set<String> getScope() {
    return this.scope;
  }

  public String getFlowType() {
    return flowType;
  }

  public HttpServletRequest getRequest() {
    return request;
  }
}