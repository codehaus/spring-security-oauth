package org.springframework.security.oauth.common.signature;

import junit.framework.TestCase;

/**
 * @author Ryan Heaton
 */
public class TestPlainTextSignatureMethod extends TestCase {

  /**
   * tests signing and verifying.
   */
  public void testSignAndVerify() throws Exception {
    String baseString = "thisismysignaturebasestringthatshouldbemuchlongerthanthisbutitdoesnthavetobeandherearesomestrangecharacters!@#$%^&*)(*";
    PlainTextSignatureMethod signatureMethod = new PlainTextSignatureMethod("shhhhhhhh");
    String signature = signatureMethod.sign(baseString);
    signatureMethod.verify(baseString, signature);
  }

}