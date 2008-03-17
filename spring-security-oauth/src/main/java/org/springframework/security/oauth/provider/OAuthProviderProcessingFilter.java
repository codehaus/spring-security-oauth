package org.springframework.security.oauth.provider;

import org.acegisecurity.AcegiMessageSource;
import org.acegisecurity.Authentication;
import org.acegisecurity.AuthenticationException;
import org.acegisecurity.context.SecurityContextHolder;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.signature.*;
import org.springframework.security.oauth.provider.nonce.ExpiringTimestampNonceServices;
import org.springframework.security.oauth.provider.nonce.OAuthNonceServices;
import org.springframework.security.oauth.provider.token.OAuthProviderToken;
import org.springframework.security.oauth.provider.token.OAuthProviderTokenServices;
import org.springframework.util.Assert;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

/**
 * OAuth processing filter. This filter should be applied to requests for OAuth protected resources (see OAuth Core 1.0).<br/><br/>
 *
 * @author Ryan Heaton
 */
public abstract class OAuthProviderProcessingFilter implements Filter, InitializingBean, MessageSourceAware {

  private static final Log LOG = LogFactory.getLog(OAuthProviderProcessingFilter.class);
  private final List<String> allowedMethods = new ArrayList<String>(Arrays.asList("GET", "POST"));
  private OAuthProcessingFilterEntryPoint authenticationEntryPoint = new OAuthProcessingFilterEntryPoint();
  protected MessageSourceAccessor messages = AcegiMessageSource.getAccessor();
  private String filterProcessesUrl = "/oauth_filter";
  private OAuthProviderSupport providerSupport = new CoreOAuthProviderSupport();
  private OAuthSignatureMethodFactory signatureMethodFactory = new CoreOAuthSignatureMethodFactory();
  private OAuthNonceServices nonceServices = new ExpiringTimestampNonceServices();
  private boolean ignoreMissingCredentials = false;

  private OAuthProviderTokenServices tokenServices;
  private ConsumerDetailsService consumerDetailsService;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(consumerDetailsService, "A consumer details service is required.");
    Assert.notNull(tokenServices, "OAuth token services are required.");
  }

  public void init(FilterConfig ignored) throws ServletException {
  }

  public void destroy() {
  }

  public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
    HttpServletRequest request = (HttpServletRequest) servletRequest;
    HttpServletResponse response = (HttpServletResponse) servletResponse;

    if (requiresAuthentication(request, response, chain)) {
      if (!allowMethod(request.getMethod().toUpperCase())) {
        response.sendError(HttpServletResponse.SC_METHOD_NOT_ALLOWED);
        return;
      }

      try {
        Map<String, String> oauthParams = getProviderSupport().parseParameters(request);

        if (!oauthParams.isEmpty()) {
          String consumerKey = oauthParams.get(OAuthConsumerParameter.oauth_consumer_key.toString());
          if (consumerKey == null) {
            throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.missingConsumerKey", "Missing consumer key."));
          }

          //load the consumer details.
          ConsumerDetails consumerDetails = getConsumerDetailsService().loadConsumerByConsumerKey(consumerKey);

          //validate the parameters for the consumer.
          validateOAuthParams(consumerDetails, oauthParams);

          //extract the credentials.
          String token = oauthParams.get(OAuthConsumerParameter.oauth_token.toString());
          String signatureMethod = oauthParams.get(OAuthConsumerParameter.oauth_signature_method.toString());
          String signature = oauthParams.get(OAuthConsumerParameter.oauth_signature.toString());
          String signatureBaseString = getProviderSupport().getSignatureBaseString(request);
          ConsumerCredentials credentials = new ConsumerCredentials(consumerKey, signature, signatureMethod, signatureBaseString, token);

          //create an authentication request.
          ConsumerAuthentication authentication = new ConsumerAuthentication(consumerDetails, credentials);
          authentication.setDetails(createDetails(request, consumerDetails));

          Authentication previousAuthentication = SecurityContextHolder.getContext().getAuthentication();
          try {
            //set the authentication request (unauthenticated) into the context.
            SecurityContextHolder.getContext().setAuthentication(authentication);

            //validate the signature.
            validateSignature(authentication);

            //mark the authentication request as validated.
            authentication.setSignatureValidated(true);

            //go.
            onValidSignature(request, response, chain);
          }
          finally {
            //clear out the consumer authentication to make sure it doesn't get cached.
            resetPreviousAuthentication(previousAuthentication);
          }
        }
        else if (!isIgnoreMissingCredentials()) {
          throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.missingCredentials", "Missing OAuth consumer credentials."));
        }
        else {
          chain.doFilter(request, response);
        }
      }
      catch (AuthenticationException ae) {
        fail(request, response, ae);
      }
      catch (ServletException e) {
        if (e.getRootCause() instanceof AuthenticationException) {
          fail(request, response, (AuthenticationException) e.getRootCause());
        }
        else {
          throw e;
        }
      }
    }
    else {
      chain.doFilter(servletRequest, servletResponse);
    }
  }

  protected void resetPreviousAuthentication(Authentication previousAuthentication) {
    SecurityContextHolder.getContext().setAuthentication(previousAuthentication);
  }

  /**
   * Create the details for the authentication request.
   *
   * @param request The request.
   * @param consumerDetails The consumer details.
   * @return The authentication details.
   */
  protected Object createDetails(HttpServletRequest request, ConsumerDetails consumerDetails) {
    return new OAuthAuthenticationDetails(request, consumerDetails);
  }

  /**
   * Whether to allow the specified HTTP method.
   *
   * @param method The HTTP method to check for allowing.
   * @return Whether to allow the specified method.
   */
  protected boolean allowMethod(String method) {
    return allowedMethods.contains(method);
  }

  /**
   * Validate the signature of the request given the authentication request.
   *
   * @param authentication The authentication request.
   */
  protected void validateSignature(ConsumerAuthentication authentication) throws AuthenticationException {
    SignatureSecret secret = authentication.getConsumerDetails().getSignatureSecret();
    String token = authentication.getConsumerCredentials().getToken();
    OAuthProviderToken authToken = null;
    if (token != null) {
      authToken = getTokenServices().getToken(token);
    }

    String signatureMethod = authentication.getConsumerCredentials().getSignatureMethod();
    OAuthSignatureMethod method = getSignatureMethodFactory().getSignatureMethod(signatureMethod, secret, authToken != null ? authToken.getSecret() : null);

    String signatureBaseString = authentication.getConsumerCredentials().getSignatureBaseString();
    String signature = authentication.getConsumerCredentials().getSignature();
    method.verify(signatureBaseString, signature);
  }

  /**
   * Logic executed on valid signature. The security context can be assumed to hold a verified, authenticated
   * {@link org.springframework.security.oauth.provider.ConsumerAuthentication}.<br/><br/>
   *
   * Default implementation continues the chain.
   *
   * @param request  The request.
   * @param response The response
   * @param chain    The filter chain.
   */
  protected abstract void onValidSignature(HttpServletRequest request, HttpServletResponse response, FilterChain chain) throws IOException, ServletException;

  /**
   * Validates the OAuth parameters for the given consumer. Base implementation validates only those parameters
   * that are required for all OAuth requests. This includes the nonce and timestamp, but not the signature.
   *
   * @param consumerDetails The consumer details.
   * @param oauthParams     The OAuth parameters to validate.
   * @throws InvalidOAuthParametersException If the OAuth parameters are invalid.
   */
  protected void validateOAuthParams(ConsumerDetails consumerDetails, Map<String, String> oauthParams) throws InvalidOAuthParametersException {
    String version = oauthParams.get(OAuthConsumerParameter.oauth_version.toString());
    if ((version != null) && (!"1.0".equals(version))) {
      throw new OAuthVersionUnsupportedException("Unsupported OAuth version: " + version);
    }

    String realm = oauthParams.get("realm");
    if ((realm != null) && (!realm.equals(this.authenticationEntryPoint.getRealmName()))) {
      throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.incorrectRealm",
                                                                    new Object[]{realm, this.getAuthenticationEntryPoint().getRealmName()},
                                                                    "Response realm name '{0}' does not match system realm name of '{1}'"));
    }

    String signatureMethod = oauthParams.get(OAuthConsumerParameter.oauth_signature_method.toString());
    if (signatureMethod == null) {
      throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.missingSignatureMethod", "Missing signature method."));
    }

    String signature = oauthParams.get(OAuthConsumerParameter.oauth_signature.toString());
    if (signature == null) {
      throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.missingSignature", "Missing signature."));
    }

    String timestamp = oauthParams.get(OAuthConsumerParameter.oauth_timestamp.toString());
    if (timestamp == null) {
      throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.missingTimestamp", "Missing timestamp."));
    }

    String nonce = oauthParams.get(OAuthConsumerParameter.oauth_nonce.toString());
    if (nonce == null) {
      throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.missingNonce", "Missing nonce."));
    }

    try {
      if (getNonceServices().validateNonce(consumerDetails, Long.parseLong(timestamp), nonce)) {
        onNewTimestamp();
      }
    }
    catch (NumberFormatException e) {
      throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.invalidTimestamp", new Object[]{timestamp}, "Timestamp must be a positive integer. Invalid value: {0}"));
    }

    //todo: validate no unsupported parameters?
    //todo: validate no duplicate parameters?
  }

  /**
   * Logic to be performed on a new timestamp.  The default behavior expects that the timestamp should not be new.
   *
   * @throws org.acegisecurity.AuthenticationException
   *          If the timestamp shouldn't be new.
   */
  protected void onNewTimestamp() throws AuthenticationException {
    throw new InvalidOAuthParametersException(messages.getMessage("OAuthProcessingFilter.timestampNotNew", "A new timestamp should not be used in a request for an access token."));
  }

  /**
   * Common logic for OAuth failed.
   *
   * @param request  The request.
   * @param response The response.
   * @param failure  The failure.
   */
  protected void fail(HttpServletRequest request, HttpServletResponse response, AuthenticationException failure) throws IOException, ServletException {
    SecurityContextHolder.getContext().setAuthentication(null);

    if (LOG.isDebugEnabled()) {
      LOG.debug(failure);
    }

    if (failure instanceof InvalidOAuthParametersException) {
      response.sendError(400, failure.getMessage());
    }
    else if (failure instanceof UnsupportedSignatureMethodException) {
      response.sendError(400, failure.getMessage());
    }
    else {
      authenticationEntryPoint.commence(request, response, failure);
    }
  }

  /**
   * Whether this filter is configured to process the specified request.
   *
   * @param request     The request.
   * @param response    The response
   * @param filterChain The filter chain
   * @return Whether this filter is configured to process the specified request.
   */
  protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) {
    //copied from org.acegisecurity.ui.AbstractProcessingFilter.requiresAuthentication
    String uri = request.getRequestURI();
    int pathParamIndex = uri.indexOf(';');

    if (pathParamIndex > 0) {
      // strip everything after the first semi-colon
      uri = uri.substring(0, pathParamIndex);
    }

    if ("".equals(request.getContextPath())) {
      return uri.endsWith(filterProcessesUrl);
    }

    return uri.endsWith(request.getContextPath() + filterProcessesUrl);
  }

  /**
   * The authentication entry point.
   *
   * @return The authentication entry point.
   */
  public OAuthProcessingFilterEntryPoint getAuthenticationEntryPoint() {
    return authenticationEntryPoint;
  }

  /**
   * The authentication entry point.
   *
   * @param authenticationEntryPoint The authentication entry point.
   */
  public void setAuthenticationEntryPoint(OAuthProcessingFilterEntryPoint authenticationEntryPoint) {
    this.authenticationEntryPoint = authenticationEntryPoint;
  }

  /**
   * The consumer details service.
   *
   * @return The consumer details service.
   */
  public ConsumerDetailsService getConsumerDetailsService() {
    return consumerDetailsService;
  }

  /**
   * The consumer details service.
   *
   * @param consumerDetailsService The consumer details service.
   */
  public void setConsumerDetailsService(ConsumerDetailsService consumerDetailsService) {
    this.consumerDetailsService = consumerDetailsService;
  }

  /**
   * The nonce services.
   *
   * @return The nonce services.
   */
  public OAuthNonceServices getNonceServices() {
    return nonceServices;
  }

  /**
   * The nonce services.
   *
   * @param nonceServices The nonce services.
   */
  public void setNonceServices(OAuthNonceServices nonceServices) {
    this.nonceServices = nonceServices;
  }

  /**
   * Get the OAuth token services.
   *
   * @return The OAuth token services.
   */
  public OAuthProviderTokenServices getTokenServices() {
    return tokenServices;
  }

  /**
   * The OAuth token services.
   *
   * @param tokenServices The OAuth token services.
   */
  public void setTokenServices(OAuthProviderTokenServices tokenServices) {
    this.tokenServices = tokenServices;
  }

  /**
   * The URL for which this filter will be applied.
   *
   * @return The URL for which this filter will be applied.
   */
  public String getFilterProcessesUrl() {
    return filterProcessesUrl;
  }

  /**
   * The URL for which this filter will be applied.
   *
   * @param filterProcessesUrl The URL for which this filter will be applied.
   */
  public void setFilterProcessesUrl(String filterProcessesUrl) {
    this.filterProcessesUrl = filterProcessesUrl;
  }

  /**
   * Set the message source.
   *
   * @param messageSource The message source.
   */
  public void setMessageSource(MessageSource messageSource) {
    this.messages = new MessageSourceAccessor(messageSource);
  }

  /**
   * The OAuth provider support.
   *
   * @return The OAuth provider support.
   */
  public OAuthProviderSupport getProviderSupport() {
    return providerSupport;
  }

  /**
   * The OAuth provider support.
   *
   * @param providerSupport The OAuth provider support.
   */
  public void setProviderSupport(OAuthProviderSupport providerSupport) {
    this.providerSupport = providerSupport;
  }

  /**
   * The OAuth signature method factory.
   *
   * @return The OAuth signature method factory.
   */
  public OAuthSignatureMethodFactory getSignatureMethodFactory() {
    return signatureMethodFactory;
  }

  /**
   * The OAuth signature method factory.
   *
   * @param signatureMethodFactory The OAuth signature method factory.
   */
  public void setSignatureMethodFactory(OAuthSignatureMethodFactory signatureMethodFactory) {
    this.signatureMethodFactory = signatureMethodFactory;
  }

  /**
   * Whether to ignore missing OAuth credentials.
   *
   * @return Whether to ignore missing OAuth credentials.
   */
  public boolean isIgnoreMissingCredentials() {
    return ignoreMissingCredentials;
  }

  /**
   * Whether to ignore missing OAuth credentials.
   *
   * @param ignoreMissingCredentials Whether to ignore missing OAuth credentials.
   */
  public void setIgnoreMissingCredentials(boolean ignoreMissingCredentials) {
    this.ignoreMissingCredentials = ignoreMissingCredentials;
  }

  /**
   * The allowed set of HTTP methods.
   *
   * @param allowedMethods The allowed set of methods.
   */
  public void setAllowedMethods(List<String> allowedMethods) {
    this.allowedMethods.clear();
    if (allowedMethods != null) {
      for (String allowedMethod : allowedMethods) {
        this.allowedMethods.add(allowedMethod.toUpperCase());
      }
    }
  }
}
