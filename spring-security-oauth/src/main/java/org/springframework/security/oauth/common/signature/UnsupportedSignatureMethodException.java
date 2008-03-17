package org.springframework.security.oauth.common.signature;

import org.springframework.security.oauth.common.OAuthException;

/**
 * @author Ryan Heaton
 */
public class UnsupportedSignatureMethodException extends OAuthException {

  public UnsupportedSignatureMethodException(String msg) {
    super(msg);
  }
}
