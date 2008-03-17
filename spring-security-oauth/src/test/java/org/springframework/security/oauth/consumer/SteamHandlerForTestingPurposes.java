package org.springframework.security.oauth.consumer;

import sun.net.www.protocol.http.Handler;

import java.net.URLConnection;
import java.net.URL;
import java.net.Proxy;
import java.io.IOException;

/**
 * @author Ryan Heaton
 */
public class SteamHandlerForTestingPurposes extends Handler {

  private final HttpURLConnectionForTestingPurposes connection;

  public SteamHandlerForTestingPurposes(HttpURLConnectionForTestingPurposes connection) {
    this.connection = connection;
  }

  @Override
  protected URLConnection openConnection(URL url) throws IOException {
    return connection;
  }

  @Override
  protected URLConnection openConnection(URL url, Proxy proxy) throws IOException {
    return connection;
  }
}
