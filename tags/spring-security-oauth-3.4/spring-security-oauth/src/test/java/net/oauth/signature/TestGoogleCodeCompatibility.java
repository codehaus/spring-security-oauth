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

package net.oauth.signature;

import junit.framework.TestCase;
import org.springframework.security.oauth.common.signature.HMAC_SHA1SignatureMethod;

import javax.crypto.spec.SecretKeySpec;

/**
 * @author Ryan Heaton
 */
public class TestGoogleCodeCompatibility extends TestCase {

  /**
   * tests compatibilty with the google code HMAC_SHA1 signature.
   */
  public void testHMAC_SHA1_1() throws Exception {
    HMAC_SHA1 theirMethod = new HMAC_SHA1();
    String baseString = "GET&http%3A%2F%2Flocalhost%3A8080%2Fgrailscrowd%2Foauth%2Frequest_token&oauth_consumer_key%3Dtonrconsumerkey%26oauth_nonce%3D1227967049787975000%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1227967049%26oauth_version%3D1.0";
    theirMethod.setConsumerSecret("xxxxxx");
    theirMethod.setTokenSecret("");
    SecretKeySpec spec = new SecretKeySpec("xxxxxx&".getBytes("UTF-8"), HMAC_SHA1SignatureMethod.MAC_NAME);
    HMAC_SHA1SignatureMethod ourMethod = new HMAC_SHA1SignatureMethod(spec);
    String theirSignature = theirMethod.getSignature(baseString);
    String ourSignature = ourMethod.sign(baseString);
    assertEquals(theirSignature, ourSignature);
  }

}
