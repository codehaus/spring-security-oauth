package org.springframework.security.oauth.consumer;

import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;
import org.springframework.security.oauth.consumer.nonce.NonceFactory;
import org.springframework.security.oauth.consumer.nonce.UUIDNonceFactory;
import org.springframework.security.oauth.consumer.net.OAuthURLStreamHandlerFactory;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.OAuthProviderParameter;
import org.springframework.security.oauth.common.OAuthCodec;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethodFactory;
import org.springframework.security.oauth.common.signature.CoreOAuthSignatureMethodFactory;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethod;
import static org.springframework.security.oauth.common.OAuthCodec.oauthEncode;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.acegisecurity.util.StringSplitUtils;
import org.apache.commons.codec.DecoderException;

import java.net.*;
import java.util.*;
import java.io.*;

/**
 * Consumer-side support for OAuth. This support uses a {@link java.net.URLConnection} to interface with the
 * OAuth provider.  A proxy will be selected, but it is assumed that the {@link javax.net.ssl.TrustManager}s
 * and other connection-related environment variables are already set up.
 *
 * @author Ryan Heaton
 */
public class CoreOAuthConsumerSupport implements OAuthConsumerSupport, InitializingBean {

  private OAuthURLStreamHandlerFactory streamHandlerFactory;
  private OAuthSignatureMethodFactory signatureFactory = new CoreOAuthSignatureMethodFactory();
  private NonceFactory nonceFactory = new UUIDNonceFactory();

  private ProtectedResourceDetailsService protectedResourceDetailsService;

  private ProxySelector proxySelector = ProxySelector.getDefault();
  private int connectionTimeout = 1000 * 60;
  private int readTimeout = 1000 * 60;

  public void afterPropertiesSet() throws Exception {
    Assert.notNull(protectedResourceDetailsService, "A protected resource details service is required.");

    if (streamHandlerFactory == null) {
      try {
        streamHandlerFactory = (OAuthURLStreamHandlerFactory) Class.forName("org.springframework.security.oauth.consumer.net.DefaultOAuthURLStreamHandlerFactory").newInstance();
      }
      catch (Throwable error) {
        throw new IllegalStateException("A stream handler factory is required.");
      }
    }
  }

  // Inherited.
  public OAuthConsumerToken getUnauthorizedRequestToken(String resourceId) throws OAuthRequestFailedException {
    ProtectedResourceDetails details = getProtectedResourceDetailsService().loadProtectedResourceDetailsById(resourceId);

    URL requestTokenURL;
    try {
      requestTokenURL = new URL(details.getRequestTokenURL());
    }
    catch (MalformedURLException e) {
      throw new IllegalStateException("Malformed URL for obtaining a request token.", e);
    }

    return getTokenFromProvider(details, requestTokenURL, null);
  }

  // Inherited.
  public OAuthConsumerToken getAccessToken(OAuthConsumerToken requestToken) throws OAuthRequestFailedException {
    ProtectedResourceDetails details = getProtectedResourceDetailsService().loadProtectedResourceDetailsById(requestToken.getResourceId());

    URL accessTokenURL;
    try {
      accessTokenURL = new URL(details.getAccessTokenURL());
    }
    catch (MalformedURLException e) {
      throw new IllegalStateException("Malformed URL for obtaining an access token.", e);
    }

    return getTokenFromProvider(details, accessTokenURL, requestToken);
  }

  // Inherited.
  public InputStream readProtectedResource(URL url, OAuthConsumerToken accessToken) throws OAuthRequestFailedException {
    if (accessToken == null) {
      throw new OAuthRequestFailedException("A valid access token must be supplied.");
    }

    ProtectedResourceDetails resourceDetails = getProtectedResourceDetailsService().loadProtectedResourceDetailsById(accessToken.getResourceId());
    return readResouce(resourceDetails, url, accessToken);
  }

  /**
   * Read a resource.
   *
   * @param details The details.
   * @param url     The URL.
   * @param token   The token to use for access.
   * @return The resource.
   */
  protected InputStream readResouce(ProtectedResourceDetails details, URL url, OAuthConsumerToken token) {
    String realm = details.getAuthorizationHeaderRealm();
    url = configureURLForProtectedAccess(url, token, details);
    String httpMethod = details.getHTTPMethod();
    if (httpMethod == null) {
      httpMethod = "POST";
    }

    boolean sendOAuthParamsInRequestBody = !details.isAcceptsAuthorizationHeader() && ("POST".equalsIgnoreCase(httpMethod) || "PUT".equalsIgnoreCase(httpMethod));
    HttpURLConnection connection = openConnection(url);

    try {
      connection.setRequestMethod(httpMethod);
    }
    catch (ProtocolException e) {
      throw new IllegalStateException(e);
    }

    int responseCode;
    String responseMessage;
    try {
      connection.setDoOutput(sendOAuthParamsInRequestBody);
      connection.connect();
      if (sendOAuthParamsInRequestBody) {
        String queryString = getOAuthQueryString(details, token, url);
        OutputStream out = connection.getOutputStream();
        out.write(queryString.getBytes("UTF-8"));
        out.flush();
        out.close();
      }
      responseCode = connection.getResponseCode();
      responseMessage = connection.getResponseMessage();
      if (responseMessage == null) {
        responseMessage = "Unknown Error";
      }
    }
    catch (IOException e) {
      throw new OAuthRequestFailedException("OAuth connection failed.", e);
    }

    if (responseCode >= 200 && responseCode < 300) {
      try {
        return connection.getInputStream();
      }
      catch (IOException e) {
        throw new OAuthRequestFailedException("Unable to get the input stream from a successful response.", e);
      }
    }
    else if (responseCode == 400) {
      throw new OAuthRequestFailedException("OAuth authentication failed: " + responseMessage);
    }
    else if (responseCode == 401) {
      String authHeaderValue = connection.getHeaderField("WWW-Authenticate");
      if (authHeaderValue != null) {
        Map<String, String> headerEntries = StringSplitUtils.splitEachArrayElementAndCreateMap(StringSplitUtils.splitIgnoringQuotes(authHeaderValue, ','), "=", "\"");
        String requiredRealm = headerEntries.get("realm");
        if ((requiredRealm != null) && (!requiredRealm.equals(realm))) {
          throw new InvalidOAuthRealmException(String.format("Invalid OAuth realm. Provider expects \"%s\", when the resource details specify \"%s\".", requiredRealm, realm), requiredRealm);
        }
      }

      throw new OAuthRequestFailedException("OAuth authentication failed: " + responseMessage);
    }
    else {
      throw new OAuthRequestFailedException(String.format("Invalid response code %s (%s).", responseCode, responseMessage));
    }
  }

  /**
   * Create a configured URL.  If the HTTP method to access the resource is "POST" or "PUT" and the "Authorization"
   * header isn't supported, then the OAuth parameters will be expected to be sent in the body of the request. Otherwise,
   * you can assume that the given URL is ready to be used without further work.
   *
   * @param url         The base URL.
   * @param accessToken The access token.
   * @return The configured URL.
   */
  public URL configureURLForProtectedAccess(URL url, OAuthConsumerToken accessToken) throws OAuthRequestFailedException {
    return configureURLForProtectedAccess(url, accessToken, getProtectedResourceDetailsService().loadProtectedResourceDetailsById(accessToken.getResourceId()));
  }

  /**
   * Internal use of configuring the URL for protected access, the resource details already having been loaded.
   *
   * @param url          The URL.
   * @param requestToken The request token.
   * @param details      The details.
   * @return The configured URL.
   */
  protected URL configureURLForProtectedAccess(URL url, OAuthConsumerToken requestToken, ProtectedResourceDetails details) {
    StringBuilder file = new StringBuilder(url.getPath());
    String httpMethod = details.getHTTPMethod();
    if (httpMethod == null) {
      httpMethod = "POST"; //post is the default.
    }

    if (!"POST".equalsIgnoreCase(httpMethod) && !"PUT".equalsIgnoreCase(httpMethod)) {
      String queryString = getOAuthQueryString(details, requestToken, url);
      file.append('?').append(queryString);
    }

    try {
      if ("http".equalsIgnoreCase(url.getProtocol())) {
        URLStreamHandler streamHandler = getStreamHandlerFactory().getHttpStreamHandler(details, requestToken, this);
        return new URL(url.getProtocol(), url.getHost(), url.getPort(), file.toString(), streamHandler);
      }
      else if ("https".equalsIgnoreCase(url.getProtocol())) {
        URLStreamHandler streamHandler = getStreamHandlerFactory().getHttpsStreamHandler(details, requestToken, this);
        return new URL(url.getProtocol(), url.getHost(), url.getPort(), file.toString(), streamHandler);
      }
      else {
        throw new OAuthRequestFailedException("Unsupport OAuth protocol: " + url.getProtocol());
      }
    }
    catch (MalformedURLException e) {
      throw new IllegalStateException(e);
    }
  }

  // Inherited.
  public String getAuthorizationHeader(ProtectedResourceDetails details, OAuthConsumerToken accessToken, URL url) {
    if (!details.isAcceptsAuthorizationHeader()) {
      return null;
    }
    else {
      Map<String, String> oauthParams = loadOAuthParameters(details, url, accessToken);
      String realm = details.getAuthorizationHeaderRealm();

      StringBuilder builder = new StringBuilder("OAuth ");
      boolean writeComma = false;
      if (realm != null) { //realm is optional.
        builder.append("realm=\"").append(realm).append('"');
        writeComma = true;
      }

      OAuthConsumerParameter[] parameters = OAuthConsumerParameter.values();
      for (int i = 0; i < parameters.length; i++) {
        OAuthConsumerParameter parameter = parameters[i];
        String paramValue = oauthParams.get(parameter.toString());
        if (paramValue != null) { //token is optional.
          if (writeComma) {
            writeComma = false;
            builder.append(", ");
          }

          builder.append(oauthEncode(parameter.toString())).append("=\"").append(oauthEncode(paramValue)).append('"');
          writeComma = true;
        }
      }

      return builder.toString();
    }
  }

  // Inherited.
  public String getOAuthQueryString(ProtectedResourceDetails details, OAuthConsumerToken accessToken, URL url) {
    Map<String, String> oauthParams = loadOAuthParameters(details, url, accessToken);

    StringBuilder queryString = new StringBuilder();
    if (details.isAcceptsAuthorizationHeader()) {
      //if the resource accepts the authorization header, the oauth parameters will go in a header and not in the query.
      for (OAuthConsumerParameter oauthParam : OAuthConsumerParameter.values()) {
        oauthParams.remove(oauthParam.toString());
      }
    }

    Iterator<String> parametersIt = oauthParams.keySet().iterator();
    while (parametersIt.hasNext()) {
      String parameter = parametersIt.next();
      String parameterValue = oauthParams.get(parameter);
      try {
        queryString.append(URLEncoder.encode(parameter, "UTF-8"));
        if (parameterValue != null) {
          queryString.append('=').append(URLEncoder.encode(parameterValue, "UTF-8"));
        }
        if (parametersIt.hasNext()) {
          queryString.append('&');
        }
      }
      catch (UnsupportedEncodingException e) {
        throw new IllegalStateException(e);
      }
    }

    return queryString.toString();
  }

  /**
   * Get the consumer token with the given parameters and URL. The determination of whether the retrieved token
   * is an access token depends on whether a request token is provided.
   *
   * @param details      The resource details.
   * @param tokenURL     The token URL.
   * @param requestToken The request token, or null if none.
   * @return The token.
   */
  protected OAuthConsumerToken getTokenFromProvider(ProtectedResourceDetails details, URL tokenURL, OAuthConsumerToken requestToken) {
    boolean isAccessToken = requestToken != null;
    if (!isAccessToken) {
      //create an empty token to make a request for a new unauthorized request token.
      requestToken = new OAuthConsumerToken();
      requestToken.setNonce(getNonceFactory().generateNonce());
    }

    InputStream inputStream = readResouce(details, tokenURL, requestToken);
    String tokenInfo;
    try {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      byte[] buffer = new byte[1024];
      int len = inputStream.read(buffer);
      while (len >= 0) {
        out.write(buffer, 0, len);
        len = inputStream.read(buffer);
      }

      tokenInfo = new String(out.toByteArray(), "UTF-8");
    }
    catch (IOException e) {
      throw new OAuthRequestFailedException("Unable to read the token.", e);
    }

    StringTokenizer tokenProperties = new StringTokenizer(tokenInfo, "&");
    Map<String, String> tokenPropertyValues = new TreeMap<String, String>();
    while (tokenProperties.hasMoreElements()) {
      try {
        String tokenProperty = (String) tokenProperties.nextElement();
        int equalsIndex = tokenProperty.indexOf('=');
        if (equalsIndex > 0) {
          String propertyName = OAuthCodec.oauthDecode(tokenProperty.substring(0, equalsIndex));
          String propertyValue = OAuthCodec.oauthDecode(tokenProperty.substring(equalsIndex + 1));
          tokenPropertyValues.put(propertyName, propertyValue);
        }
        else {
          tokenProperty = OAuthCodec.oauthDecode(tokenProperty);
          tokenPropertyValues.put(tokenProperty, null);
        }
      }
      catch (DecoderException e) {
        throw new OAuthRequestFailedException("Unable to decode token parameters.");
      }
    }

    String tokenValue = tokenPropertyValues.get(OAuthProviderParameter.oauth_token.toString());
    if (tokenValue == null) {
      throw new OAuthRequestFailedException("OAuth provider failed to return a token.");
    }

    String tokenSecret = tokenPropertyValues.get(OAuthProviderParameter.oauth_token_secret.toString());
    if (tokenSecret == null) {
      throw new OAuthRequestFailedException("OAuth provider failed to return a token secret.");
    }

    OAuthConsumerToken consumerToken = new OAuthConsumerToken();
    consumerToken.setValue(tokenValue);
    consumerToken.setSecret(tokenSecret);
    consumerToken.setNonce(requestToken.getNonce());
    consumerToken.setResourceId(details.getId());
    consumerToken.setAccessToken(isAccessToken);
    return consumerToken;
  }

  /**
   * Loads the OAuth parameters for the given resource at the given URL and the given token. These parameters include
   * any query parameters on the URL since they are included in the signature.
   *
   * @param details      The resource details.
   * @param requestURL   The request URL.
   * @param requestToken The request token.
   * @return The parameters.
   */
  protected Map<String, String> loadOAuthParameters(ProtectedResourceDetails details, URL requestURL, OAuthConsumerToken requestToken) {
    String httpMethod = details.getHTTPMethod();
    if ((httpMethod == null) || (httpMethod.length() == 0)) {
      httpMethod = "POST";
    }

    Map<String, String> oauthParams = new TreeMap<String, String>();
    String query = requestURL.getQuery();
    if (query != null) {
      StringTokenizer queryTokenizer = new StringTokenizer(query, "&");
      while (queryTokenizer.hasMoreElements()) {
        String token = (String) queryTokenizer.nextElement();
        if (token.indexOf('=') < 0) {
          oauthParams.put(token, null);
        }
        else {
          int equalsIndex = token.indexOf('=');
          if (equalsIndex < 0) {
            oauthParams.put(token, null);
          }
          else {
            String paramName = token.substring(0, equalsIndex);
            String paramValue = token.substring(equalsIndex + 1);
            oauthParams.put(paramName, paramValue);
          }
        }
      }
    }

    String tokenSecret = requestToken == null ? null : requestToken.getSecret();
    String nonce = requestToken == null ? getNonceFactory().generateNonce() : requestToken.getNonce();
    oauthParams.put(OAuthConsumerParameter.oauth_consumer_key.toString(), details.getConsumerKey());
    if ((requestToken != null) && (requestToken.getValue() != null)) {
      oauthParams.put(OAuthConsumerParameter.oauth_token.toString(), requestToken.getValue());
    }

    oauthParams.put(OAuthConsumerParameter.oauth_nonce.toString(), nonce);
    oauthParams.put(OAuthConsumerParameter.oauth_signature_method.toString(), details.getSignatureMethod());
    oauthParams.put(OAuthConsumerParameter.oauth_timestamp.toString(), String.valueOf(System.currentTimeMillis() / 1000));
    oauthParams.put(OAuthConsumerParameter.oauth_version.toString(), "1.0");
    String signatureBaseString = getSignatureBaseString(oauthParams, requestURL, httpMethod);
    OAuthSignatureMethod signatureMethod = getSignatureFactory().getSignatureMethod(details.getSignatureMethod(), details.getSharedSecret(), tokenSecret);
    String signature = signatureMethod.sign(signatureBaseString);
    oauthParams.put(OAuthConsumerParameter.oauth_signature.toString(), signature);
    return oauthParams;
  }

  /**
   * Open a connection to the given URL.
   *
   * @param requestTokenURL The request token URL.
   * @return The HTTP URL connection.
   */
  protected HttpURLConnection openConnection(URL requestTokenURL) {
    try {
      HttpURLConnection connection = (HttpURLConnection) requestTokenURL.openConnection(selectProxy(requestTokenURL));
      connection.setConnectTimeout(getConnectionTimeout());
      connection.setReadTimeout(getReadTimeout());
      return connection;
    }
    catch (IOException e) {
      throw new OAuthRequestFailedException("Failed to open an OAuth connection.", e);
    }
  }

  /**
   * Selects a proxy for the given URL.
   *
   * @param requestTokenURL The URL
   * @return The proxy.
   */
  protected Proxy selectProxy(URL requestTokenURL) {
    try {
      List<Proxy> selectedProxies = getProxySelector().select(requestTokenURL.toURI());
      return selectedProxies.isEmpty() ? Proxy.NO_PROXY : selectedProxies.get(0);
    }
    catch (URISyntaxException e) {
      throw new IllegalArgumentException(e);
    }
  }

  /**
   * Get the signature base string for the specified parameters.
   *
   * @param oauthParams The parameters.
   * @param requestURL  The request URL.
   * @param httpMethod  The http method.
   * @return The signature base string.
   */
  protected String getSignatureBaseString(Map<String, String> oauthParams, URL requestURL, String httpMethod) {
    //now sort them (according to the spec.
    Map.Entry<String, String>[] sortedParameters = oauthParams.entrySet().toArray(new Map.Entry[oauthParams.size()]);
    Comparator<Map.Entry<String, String>> parameterComparator = new Comparator<Map.Entry<String, String>>() {
      public int compare(Map.Entry<String, String> param1, Map.Entry<String, String> param2) {
        int comparison = param1.getKey().compareTo(param2.getKey());
        if (comparison == 0) {
          String value1 = param1.getValue();
          if (value1 == null) {
            value1 = "";
          }

          String value2 = param2.getValue();
          if (value2 == null) {
            value2 = "";
          }

          comparison = value1.compareTo(value2);
        }
        return comparison;
      }
    };
    Arrays.sort(sortedParameters, parameterComparator);

    //now concatenate them into a single query string according to the spec.
    StringBuilder queryString = new StringBuilder();
    for (int i = 0; i < sortedParameters.length; i++) {
      Map.Entry<String, String> sortedParameter = sortedParameters[i];
      String parameterValue = sortedParameter.getValue();
      if (parameterValue == null) {
        parameterValue = "";
      }
      queryString.append(sortedParameter.getKey()).append('=').append(parameterValue);
      if (i + 1 < sortedParameters.length) {
        queryString.append('&');
      }
    }

    StringBuilder url = new StringBuilder(requestURL.getProtocol().toLowerCase()).append("://").append(requestURL.getHost().toLowerCase());
    if ((requestURL.getPort() >= 0) && (requestURL.getPort() != requestURL.getDefaultPort())) {
      url.append(":").append(requestURL.getPort());
    }
    url.append(requestURL.getPath());

    return new StringBuilder(httpMethod.toUpperCase()).append('&').append(oauthEncode(url.toString())).append('&').append(oauthEncode(queryString.toString())).toString();
  }

  /**
   * The protected resource details service.
   *
   * @return The protected resource details service.
   */
  public ProtectedResourceDetailsService getProtectedResourceDetailsService() {
    return protectedResourceDetailsService;
  }

  /**
   * The protected resource details service.
   *
   * @param protectedResourceDetailsService
   *         The protected resource details service.
   */
  public void setProtectedResourceDetailsService(ProtectedResourceDetailsService protectedResourceDetailsService) {
    this.protectedResourceDetailsService = protectedResourceDetailsService;
  }

  /**
   * The URL stream handler factory for connections to an OAuth resource.
   *
   * @return The URL stream handler factory for connections to an OAuth resource.
   */
  public OAuthURLStreamHandlerFactory getStreamHandlerFactory() {
    return streamHandlerFactory;
  }

  /**
   * The URL stream handler factory for connections to an OAuth resource.
   *
   * @param streamHandlerFactory The URL stream handler factory for connections to an OAuth resource.
   */
  public void setStreamHandlerFactory(OAuthURLStreamHandlerFactory streamHandlerFactory) {
    this.streamHandlerFactory = streamHandlerFactory;
  }

  /**
   * The nonce factory.
   *
   * @return The nonce factory.
   */
  public NonceFactory getNonceFactory() {
    return nonceFactory;
  }

  /**
   * The nonce factory.
   *
   * @param nonceFactory The nonce factory.
   */
  public void setNonceFactory(NonceFactory nonceFactory) {
    this.nonceFactory = nonceFactory;
  }

  /**
   * The signature factory to use.
   *
   * @return The signature factory to use.
   */
  public OAuthSignatureMethodFactory getSignatureFactory() {
    return signatureFactory;
  }

  /**
   * The signature factory to use.
   *
   * @param signatureFactory The signature factory to use.
   */
  public void setSignatureFactory(OAuthSignatureMethodFactory signatureFactory) {
    this.signatureFactory = signatureFactory;
  }

  /**
   * The proxy selector to use.
   *
   * @return The proxy selector to use.
   */
  public ProxySelector getProxySelector() {
    return proxySelector;
  }

  /**
   * The proxy selector to use.
   *
   * @param proxySelector The proxy selector to use.
   */
  public void setProxySelector(ProxySelector proxySelector) {
    this.proxySelector = proxySelector;
  }

  /**
   * The connection timeout (default 60 seconds).
   *
   * @return The connection timeout.
   */
  public int getConnectionTimeout() {
    return connectionTimeout;
  }

  /**
   * The connection timeout.
   *
   * @param connectionTimeout The connection timeout.
   */
  public void setConnectionTimeout(int connectionTimeout) {
    this.connectionTimeout = connectionTimeout;
  }

  /**
   * The read timeout (default 60 seconds).
   *
   * @return The read timeout.
   */
  public int getReadTimeout() {
    return readTimeout;
  }

  /**
   * The read timeout.
   *
   * @param readTimeout The read timeout.
   */
  public void setReadTimeout(int readTimeout) {
    this.readTimeout = readTimeout;
  }
}
