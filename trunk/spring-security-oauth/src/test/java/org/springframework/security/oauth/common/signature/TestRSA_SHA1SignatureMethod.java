/*
 * Copyright 2008 Web Cohesion
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.oauth.common.signature;

import junit.framework.TestCase;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;

/**
 * @author Ryan Heaton
 */
public class TestRSA_SHA1SignatureMethod extends TestCase {

  /**
   * tests signing and verifying.
   */
  public void testSignAndVerify() throws Exception {
    KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
    generator.initialize(1024);
    KeyPair keyPair = generator.generateKeyPair();
    String baseString = "thisismysignaturebasestringthatshouldbemuchlongerthanthisbutitdoesnthavetobeandherearesomestrangecharacters!@#$%^&*)(*";

    byte[] signatureBytes;
    {
      Signature signer = Signature.getInstance("SHA1withRSA");
      signer.initSign(keyPair.getPrivate());
      signer.update(baseString.getBytes("UTF-8"));
      signatureBytes = signer.sign();
    }

    {
      Signature signer = Signature.getInstance("SHA1withRSA");
      signer.initVerify(keyPair.getPublic());
      signer.update(baseString.getBytes("UTF-8"));
      assertTrue(signer.verify(signatureBytes));
    }

    RSA_SHA1SignatureMethod signatureMethod = new RSA_SHA1SignatureMethod(keyPair.getPrivate(), keyPair.getPublic());
    String signature = signatureMethod.sign(baseString);
    signatureMethod.verify(baseString, signature);
  }

}
