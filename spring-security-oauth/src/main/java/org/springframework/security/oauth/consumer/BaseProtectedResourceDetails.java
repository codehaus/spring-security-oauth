package org.springframework.security.oauth.consumer;

import org.springframework.security.oauth.common.signature.SignatureSecret;

/**
 * Basic implementation of protected resource details.
 *
 * @author Ryan Heaton
 */
public class BaseProtectedResourceDetails implements ProtectedResourceDetails {

  private String id;
  private String consumerKey;
  private String signatureMethod;
  private SignatureSecret sharedSecret;
  private String requestTokenURL;
  private String userAuthorizationURL;
  private String accessTokenURL;
  private String HTTPMethod = "POST";
  private boolean acceptsAuthorizationHeader = true;
  private String authorizationHeaderRealm;

  public String getId() {
    return id;
  }

  public void setId(String id) {
    this.id = id;
  }

  public String getConsumerKey() {
    return consumerKey;
  }

  public void setConsumerKey(String consumerKey) {
    this.consumerKey = consumerKey;
  }

  public String getSignatureMethod() {
    return signatureMethod;
  }

  public void setSignatureMethod(String signatureMethod) {
    this.signatureMethod = signatureMethod;
  }

  public SignatureSecret getSharedSecret() {
    return sharedSecret;
  }

  public void setSharedSecret(SignatureSecret sharedSecret) {
    this.sharedSecret = sharedSecret;
  }

  public String getRequestTokenURL() {
    return requestTokenURL;
  }

  public void setRequestTokenURL(String requestTokenURL) {
    this.requestTokenURL = requestTokenURL;
  }

  public String getUserAuthorizationURL() {
    return userAuthorizationURL;
  }

  public void setUserAuthorizationURL(String userAuthorizationURL) {
    this.userAuthorizationURL = userAuthorizationURL;
  }

  public String getAccessTokenURL() {
    return accessTokenURL;
  }

  public void setAccessTokenURL(String accessTokenURL) {
    this.accessTokenURL = accessTokenURL;
  }

  public String getHTTPMethod() {
    return HTTPMethod;
  }

  public void setHTTPMethod(String HTTPMethod) {
    this.HTTPMethod = HTTPMethod;
  }

  public boolean isAcceptsAuthorizationHeader() {
    return acceptsAuthorizationHeader;
  }

  public void setAcceptsAuthorizationHeader(boolean acceptsAuthorizationHeader) {
    this.acceptsAuthorizationHeader = acceptsAuthorizationHeader;
  }

  public String getAuthorizationHeaderRealm() {
    return authorizationHeaderRealm;
  }

  public void setAuthorizationHeaderRealm(String authorizationHeaderRealm) {
    this.authorizationHeaderRealm = authorizationHeaderRealm;
  }
}
