package org.springframework.security.oauth.provider;

import org.acegisecurity.AuthenticationException;
import org.acegisecurity.ui.AuthenticationEntryPoint;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * Entry point for OAuth authentication requests.
 *
 * @author Ryan Heaton
 */
public class OAuthProcessingFilterEntryPoint implements AuthenticationEntryPoint {

  private String realmName;

  public void commence(ServletRequest request, ServletResponse response, AuthenticationException authException) throws IOException, ServletException {
    HttpServletResponse httpResponse = (HttpServletResponse) response;
    StringBuilder headerValue = new StringBuilder("OAuth");
    if (realmName != null) {
      headerValue.append(" realm=\"").append(realmName).append('"');
    }
    httpResponse.addHeader("WWW-Authenticate", headerValue.toString());
    httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, authException.getMessage());
  }

  public String getRealmName() {
    return realmName;
  }

  public void setRealmName(String realmName) {
    this.realmName = realmName;
  }

}