package org.springframework.security.oauth.consumer;

import java.net.HttpURLConnection;
import java.net.URL;
import java.io.IOException;

/**
 * @author Ryan Heaton
 */
public class HttpURLConnectionForTestingPurposes extends HttpURLConnection {

  /**
   * Constructor for the HttpURLConnection.
   *
   * @param u the URL
   */
  public HttpURLConnectionForTestingPurposes(URL u) {
    super(u);
  }

  public void disconnect() {
  }

  public boolean usingProxy() {
    return false;
  }

  public void connect() throws IOException {
  }
}
