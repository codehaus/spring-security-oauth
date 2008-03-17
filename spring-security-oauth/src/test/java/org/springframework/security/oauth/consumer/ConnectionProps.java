package org.springframework.security.oauth.consumer;

import java.io.OutputStream;
import java.util.Map;
import java.util.TreeMap;

/**
 * @author Ryan Heaton
 */
public class ConnectionProps {

  public int responseCode;
  public String responseMessage;
  public String method;
  public Boolean doOutput;
  public Boolean connected;
  public OutputStream outputStream;
  public final Map<String,String> headerFields = new TreeMap<String, String>();

  public void reset() {
    this.responseCode = 0;
    this.responseMessage = null;
    this.method = null;
    this.doOutput = null;
    this.connected = null;
    this.outputStream = null;
    this.headerFields.clear();
  }

}
