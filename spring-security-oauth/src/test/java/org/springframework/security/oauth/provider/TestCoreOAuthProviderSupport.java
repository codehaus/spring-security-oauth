package org.springframework.security.oauth.provider;

import static org.easymock.EasyMock.*;
import org.springframework.security.oauth.common.OAuthConsumerParameter;

import junit.framework.TestCase;

import javax.servlet.http.HttpServletRequest;
import java.util.Map;
import java.util.HashMap;
import java.util.Collections;

/**
 * @author Ryan Heaton
 */
public class TestCoreOAuthProviderSupport extends TestCase {

  /**
   * tests parsing parameters.
   */
  public void testParseParameters() throws Exception {
    CoreOAuthProviderSupport support = new CoreOAuthProviderSupport();
    HttpServletRequest request = createMock(HttpServletRequest.class);
    expect(request.getHeader("Authorization")).andReturn("OAuth realm=\"http://sp.example.com/\",\n" +
      "                oauth_consumer_key=\"0685bd9184jfhq22\",\n" +
      "                oauth_token=\"ad180jjd733klru7\",\n" +
      "                oauth_signature_method=\"HMAC-SHA1\",\n" +
      "                oauth_signature=\"wOJIO9A2W5mFwDgiDvZbTSMK%2FPY%3D\",\n" +
      "                oauth_timestamp=\"137131200\",\n" +
      "                oauth_nonce=\"4572616e48616d6d65724c61686176\",\n" +
      "                oauth_version=\"1.0\"");
    replay(request);
    Map<String,String> params = support.parseParameters(request);
    verify(request);
    assertEquals("http://sp.example.com/", params.get("realm"));
    assertEquals("0685bd9184jfhq22", params.get(OAuthConsumerParameter.oauth_consumer_key.toString()));
    assertEquals("ad180jjd733klru7", params.get(OAuthConsumerParameter.oauth_token.toString()));
    assertEquals("HMAC-SHA1", params.get(OAuthConsumerParameter.oauth_signature_method.toString()));
    assertEquals("wOJIO9A2W5mFwDgiDvZbTSMK/PY=", params.get(OAuthConsumerParameter.oauth_signature.toString()));
    assertEquals("137131200", params.get(OAuthConsumerParameter.oauth_timestamp.toString()));
    assertEquals("4572616e48616d6d65724c61686176", params.get(OAuthConsumerParameter.oauth_nonce.toString()));
    assertEquals("1.0", params.get(OAuthConsumerParameter.oauth_version.toString()));
  }

  /**
   * tests getting the signature base string.
   */
  public void testGetSignatureBaseString() throws Exception {
    HttpServletRequest request = createMock(HttpServletRequest.class);
    Map<String, String> requestParameters = new HashMap<String, String>();
    requestParameters.put("oauth_consumer_key", "willbeoverwritten");
    requestParameters.put("oauth_token", "willbeoverwritten");
    requestParameters.put("oauth_signature_method", "willbeoverwritten");
    requestParameters.put("oauth_timestamp", "willbeoverwritten");
    requestParameters.put("oauth_nonce", "willbeoverwritten");
    requestParameters.put("oauth_version", "willbeoverwritten");
    requestParameters.put("file", "vacation.jpg");
    requestParameters.put("size", "original");

    expect(request.getParameterNames()).andReturn(Collections.enumeration(requestParameters.keySet()));
    for (String key : requestParameters.keySet()) {
      expect(request.getParameter(key)).andReturn(requestParameters.get(key));
    }

    expect(request.getHeader("Authorization")).andReturn("OAuth realm=\"http://sp.example.com/\",\n" +
      "                oauth_consumer_key=\"dpf43f3p2l4k3l03\",\n" +
      "                oauth_token=\"nnch734d00sl2jdk\",\n" +
      "                oauth_signature_method=\"HMAC-SHA1\",\n" +
      "                oauth_signature=\"unimportantforthistest\",\n" +
      "                oauth_timestamp=\"1191242096\",\n" +
      "                oauth_nonce=\"kllo9940pd9333jh\",\n" +
      "                oauth_version=\"1.0\"");

    expect(request.getMethod()).andReturn("gEt");
    CoreOAuthProviderSupport support = new CoreOAuthProviderSupport();
    support.setBaseUrl("http://photos.example.net/photos");

    replay(request);
    String baseString = support.getSignatureBaseString(request);
    verify(request);
    assertEquals("GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal", baseString);
    reset(request);
  }


}
