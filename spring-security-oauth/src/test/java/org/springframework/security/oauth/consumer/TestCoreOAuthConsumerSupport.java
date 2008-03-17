package org.springframework.security.oauth.consumer;

import static org.easymock.EasyMock.*;
import org.springframework.security.oauth.consumer.token.OAuthConsumerToken;
import org.springframework.security.oauth.consumer.net.DefaultOAuthURLStreamHandlerFactory;
import org.springframework.security.oauth.consumer.nonce.NonceFactory;
import org.springframework.security.oauth.common.OAuthConsumerParameter;
import org.springframework.security.oauth.common.signature.HMAC_SHA1SignatureMethod;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethodFactory;
import org.springframework.security.oauth.common.signature.SharedConsumerSecret;
import org.springframework.security.oauth.common.signature.OAuthSignatureMethod;

import junit.framework.TestCase;

import javax.servlet.http.HttpServletRequest;
import java.net.URL;
import java.net.MalformedURLException;
import java.net.ProtocolException;
import java.io.*;
import java.util.Map;
import java.util.TreeMap;
import java.util.HashMap;
import java.util.Collections;

/**
 * @author Ryan Heaton
 */
public class TestCoreOAuthConsumerSupport extends TestCase {

  /**
   * afterPropertiesSet
   */
  public void testAfterPropertiesSet() throws Exception {
    try {
      new CoreOAuthConsumerSupport().afterPropertiesSet();
      fail("should required a protected resource details service.");
    }
    catch (IllegalArgumentException e) {
    }
  }

  /**
   * readResouce
   */
  public void testReadResouce() throws Exception {
    ProtectedResourceDetails details = createMock(ProtectedResourceDetails.class);
    OAuthConsumerToken token = new OAuthConsumerToken();
    URL url = new URL("http://myhost.com/resource?with=some&query=params&too");
    final ConnectionProps connectionProps = new ConnectionProps();
    final ByteArrayInputStream inputStream = new ByteArrayInputStream(new byte[0]);
    final HttpURLConnectionForTestingPurposes connectionMock = new HttpURLConnectionForTestingPurposes(url) {
      @Override
      public void setRequestMethod(String method) throws ProtocolException {
        connectionProps.method = method;
      }

      @Override
      public void setDoOutput(boolean dooutput) {
        connectionProps.doOutput = dooutput;
      }

      @Override
      public void connect() throws IOException {
        connectionProps.connected = true;
      }

      @Override
      public OutputStream getOutputStream() throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        connectionProps.outputStream = out;
        return out;
      }

      @Override
      public int getResponseCode() throws IOException {
        return connectionProps.responseCode;
      }

      @Override
      public String getResponseMessage() throws IOException {
        return connectionProps.responseMessage;
      }

      @Override
      public InputStream getInputStream() throws IOException {
        return inputStream;
      }

      @Override
      public String getHeaderField(String name) {
        return connectionProps.headerFields.get(name);
      }
    };

    CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport() {
      @Override
      public URL configureURLForProtectedAccess(URL url, OAuthConsumerToken accessToken, ProtectedResourceDetails details) throws OAuthRequestFailedException {
        try {
          return new URL(url.getProtocol(), url.getHost(), url.getPort(), url.getFile(), new SteamHandlerForTestingPurposes(connectionMock));
        }
        catch (MalformedURLException e) {
          throw new RuntimeException(e);
        }
      }

      @Override
      public String getOAuthQueryString(ProtectedResourceDetails details, OAuthConsumerToken accessToken, URL url) {
        return "POSTBODY";
      }
    };
    support.setStreamHandlerFactory(new DefaultOAuthURLStreamHandlerFactory());

    expect(details.getAuthorizationHeaderRealm()).andReturn("realm1");
    expect(details.getHTTPMethod()).andReturn(null);
    expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
    replay(details);
    try {
      support.readResouce(details, url, token);
      fail("shouldn't have been a valid response code.");
    }
    catch (OAuthRequestFailedException e) {
      //fall through...
    }
    verify(details);
    reset(details);
    assertFalse(connectionProps.doOutput);
    assertEquals("POST", connectionProps.method);
    assertTrue(connectionProps.connected);
    connectionProps.reset();

    expect(details.getAuthorizationHeaderRealm()).andReturn(null);
    expect(details.getHTTPMethod()).andReturn("POST");
    expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
    connectionProps.responseCode = 400;
    connectionProps.responseMessage = "Nasty";
    replay(details);
    try {
      support.readResouce(details, url, token);
      fail("shouldn't have been a valid response code.");
    }
    catch (OAuthRequestFailedException e) {
      //fall through...
    }
    verify(details);
    reset(details);
    assertFalse(connectionProps.doOutput);
    assertEquals("POST", connectionProps.method);
    assertTrue(connectionProps.connected);
    connectionProps.reset();

    expect(details.getAuthorizationHeaderRealm()).andReturn(null);
    expect(details.getHTTPMethod()).andReturn("POST");
    expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
    connectionProps.responseCode = 401;
    connectionProps.responseMessage = "Bad Realm";
    connectionProps.headerFields.put("WWW-Authenticate", "realm=\"goodrealm\"");
    replay(details);
    try {
      support.readResouce(details, url, token);
      fail("shouldn't have been a valid response code.");
    }
    catch (InvalidOAuthRealmException e) {
      //fall through...
    }
    verify(details);
    reset(details);
    assertFalse(connectionProps.doOutput);
    assertEquals("POST", connectionProps.method);
    assertTrue(connectionProps.connected);
    connectionProps.reset();

    expect(details.getAuthorizationHeaderRealm()).andReturn(null);
    expect(details.getHTTPMethod()).andReturn("GET");
    expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
    connectionProps.responseCode = 200;
    connectionProps.responseMessage = "Congrats";
    replay(details);
    assertSame(inputStream, support.readResouce(details, url, token));
    verify(details);
    reset(details);
    assertFalse(connectionProps.doOutput);
    assertEquals("GET", connectionProps.method);
    assertTrue(connectionProps.connected);
    connectionProps.reset();

    expect(details.getAuthorizationHeaderRealm()).andReturn(null);
    expect(details.getHTTPMethod()).andReturn("POST");
    expect(details.isAcceptsAuthorizationHeader()).andReturn(false);
    connectionProps.responseCode = 200;
    connectionProps.responseMessage = "Congrats";
    replay(details);
    assertSame(inputStream, support.readResouce(details, url, token));
    assertEquals("POSTBODY", new String(((ByteArrayOutputStream) connectionProps.outputStream).toByteArray()));
    verify(details);
    reset(details);
    assertTrue(connectionProps.doOutput);
    assertEquals("POST", connectionProps.method);
    assertTrue(connectionProps.connected);
    connectionProps.reset();
  }

  /**
   * configureURLForProtectedAccess
   */
  public void testConfigureURLForProtectedAccess() throws Exception {
    CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport() {
      // Inherited.
      @Override
      public String getOAuthQueryString(ProtectedResourceDetails details, OAuthConsumerToken accessToken, URL url) {
        return "myquerystring";
      }
    };
    support.setStreamHandlerFactory(new DefaultOAuthURLStreamHandlerFactory());
    ProtectedResourceDetails details = createMock(ProtectedResourceDetails.class);
    OAuthConsumerToken token = new OAuthConsumerToken();
    URL url = new URL("https://myhost.com/somepath?with=some&query=params&too");

    expect(details.getHTTPMethod()).andReturn("GET");
    replay(details);
    assertEquals("https://myhost.com/somepath?myquerystring", support.configureURLForProtectedAccess(url, token, details).toString());
    verify(details);
    reset(details);

    expect(details.getHTTPMethod()).andReturn("POST");
    replay(details);
    assertEquals("https://myhost.com/somepath", support.configureURLForProtectedAccess(url, token, details).toString());
    verify(details);
    reset(details);

    expect(details.getHTTPMethod()).andReturn("PUT");
    replay(details);
    assertEquals("https://myhost.com/somepath", support.configureURLForProtectedAccess(url, token, details).toString());
    verify(details);
    reset(details);
  }

  /**
   * test getAuthorizationHeader
   */
  public void testGetAuthorizationHeader() throws Exception {
    final TreeMap<String, String> params = new TreeMap<String, String>();
    CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport() {
      @Override
      protected Map<String, String> loadOAuthParameters(ProtectedResourceDetails details, URL requestURL, OAuthConsumerToken requestToken) {
        return params;
      }
    };
    URL url = new URL("https://myhost.com/somepath?with=some&query=params&too");
    OAuthConsumerToken token = new OAuthConsumerToken();
    ProtectedResourceDetails details = createMock(ProtectedResourceDetails.class);

    expect(details.isAcceptsAuthorizationHeader()).andReturn(false);
    replay(details);
    assertNull(support.getAuthorizationHeader(details, token, url));
    verify(details);
    reset(details);

    params.put("with", "some");
    params.put("query", "params");
    params.put("too", null);
    expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
    expect(details.getAuthorizationHeaderRealm()).andReturn("myrealm");
    replay(details);
    assertEquals("OAuth realm=\"myrealm\"", support.getAuthorizationHeader(details, token, url));
    verify(details);
    reset(details);

    params.put(OAuthConsumerParameter.oauth_consumer_key.toString(), "mykey");
    params.put(OAuthConsumerParameter.oauth_nonce.toString(), "mynonce");
    params.put(OAuthConsumerParameter.oauth_timestamp.toString(), "myts");
    expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
    expect(details.getAuthorizationHeaderRealm()).andReturn("myrealm");
    replay(details);
    assertEquals("OAuth realm=\"myrealm\", oauth_consumer_key=\"mykey\", oauth_timestamp=\"myts\", oauth_nonce=\"mynonce\"", support.getAuthorizationHeader(details, token, url));
    verify(details);
    reset(details);
  }

  /**
   * getOAuthQueryString
   */
  public void testGetOAuthQueryString() throws Exception {
    final TreeMap<String, String> params = new TreeMap<String, String>();
    CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport() {
      @Override
      protected Map<String, String> loadOAuthParameters(ProtectedResourceDetails details, URL requestURL, OAuthConsumerToken requestToken) {
        return params;
      }
    };

    URL url = new URL("https://myhost.com/somepath?with=some&query=params&too");
    OAuthConsumerToken token = new OAuthConsumerToken();
    ProtectedResourceDetails details = createMock(ProtectedResourceDetails.class);

    expect(details.isAcceptsAuthorizationHeader()).andReturn(true);
    params.put("with", "some");
    params.put("query", "params");
    params.put("too", null);
    params.put(OAuthConsumerParameter.oauth_consumer_key.toString(), "mykey");
    params.put(OAuthConsumerParameter.oauth_nonce.toString(), "mynonce");
    params.put(OAuthConsumerParameter.oauth_timestamp.toString(), "myts");
    replay(details);
    assertEquals("query=params&too&with=some", support.getOAuthQueryString(details, token, url));
    verify(details);
    reset(details);

    expect(details.isAcceptsAuthorizationHeader()).andReturn(false);
    params.put("with", "some");
    params.put("query", "params");
    params.put("too", null);
    params.put(OAuthConsumerParameter.oauth_consumer_key.toString(), "mykey");
    params.put(OAuthConsumerParameter.oauth_nonce.toString(), "mynonce");
    params.put(OAuthConsumerParameter.oauth_timestamp.toString(), "myts");
    replay(details);
    assertEquals("oauth_consumer_key=mykey&oauth_nonce=mynonce&oauth_timestamp=myts&query=params&too&with=some", support.getOAuthQueryString(details, token, url));
    verify(details);
    reset(details);
  }

  /**
   * getTokenFromProvider
   */
  public void testGetTokenFromProvider() throws Exception {
    final ByteArrayInputStream in = new ByteArrayInputStream("oauth_token=mytoken&oauth_token_secret=mytokensecret".getBytes("UTF-8"));
    CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport() {
      @Override
      protected InputStream readResouce(ProtectedResourceDetails details, URL url, OAuthConsumerToken token) {
        return in;
      }
    };

    NonceFactory nonceFactory = createMock(NonceFactory.class);
    support.setNonceFactory(nonceFactory);
    ProtectedResourceDetails details = createMock(ProtectedResourceDetails.class);
    URL url = new URL("https://myhost.com/somepath?with=some&query=params&too");

    expect(nonceFactory.generateNonce()).andReturn("mynonce");
    expect(details.getId()).andReturn("resourceId");
    replay(details, nonceFactory);
    OAuthConsumerToken token = support.getTokenFromProvider(details, url, null);
    verify(details, nonceFactory);
    reset(details, nonceFactory);
    assertEquals("mynonce", token.getNonce());
    assertFalse(token.isAccessToken());
    assertEquals("mytoken", token.getValue());
    assertEquals("mytokensecret", token.getSecret());
    assertEquals("resourceId", token.getResourceId());

  }

  /**
   * loadOAuthParameters
   */
  public void testLoadOAuthParameters() throws Exception {
    ProtectedResourceDetails details = createMock(ProtectedResourceDetails.class);
    URL url = new URL("https://myhost.com/somepath?with=some&query=params&too");
    CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport() {
      @Override
      protected String getSignatureBaseString(Map<String, String> oauthParams, URL requestURL, String httpMethod) {
        return "MYSIGBASESTRING";
      }
    };
    OAuthSignatureMethodFactory sigFactory = createMock(OAuthSignatureMethodFactory.class);
    support.setSignatureFactory(sigFactory);
    OAuthConsumerToken token = new OAuthConsumerToken();
    token.setNonce("mynonce");
    OAuthSignatureMethod sigMethod = createMock(OAuthSignatureMethod.class);

    expect(details.getHTTPMethod()).andReturn("POST");
    expect(details.getConsumerKey()).andReturn("my-consumer-key");
    expect(details.getSignatureMethod()).andReturn(HMAC_SHA1SignatureMethod.SIGNATURE_NAME);
    expect(details.getSignatureMethod()).andReturn(HMAC_SHA1SignatureMethod.SIGNATURE_NAME);
    SharedConsumerSecret secret = new SharedConsumerSecret("shh!!!");
    expect(details.getSharedSecret()).andReturn(secret);
    expect(sigFactory.getSignatureMethod(HMAC_SHA1SignatureMethod.SIGNATURE_NAME, secret, null)).andReturn(sigMethod);
    expect(sigMethod.sign("MYSIGBASESTRING")).andReturn("MYSIGNATURE");

    replay(details, sigFactory, sigMethod);
    Map<String, String> params = support.loadOAuthParameters(details, url, token);
    verify(details, sigFactory, sigMethod);
    reset(details, sigFactory, sigMethod);
    assertEquals("some", params.remove("with"));
    assertEquals("params", params.remove("query"));
    assertTrue(params.containsKey("too"));
    assertNull(params.remove("too"));
    assertNull(params.remove(OAuthConsumerParameter.oauth_token.toString()));
    assertEquals("mynonce", params.remove(OAuthConsumerParameter.oauth_nonce.toString()));
    assertEquals("my-consumer-key", params.remove(OAuthConsumerParameter.oauth_consumer_key.toString()));
    assertEquals("MYSIGNATURE", params.remove(OAuthConsumerParameter.oauth_signature.toString()));
    assertEquals("1.0", params.remove(OAuthConsumerParameter.oauth_version.toString()));
    assertEquals(HMAC_SHA1SignatureMethod.SIGNATURE_NAME, params.remove(OAuthConsumerParameter.oauth_signature_method.toString()));
    assertTrue(Long.parseLong(params.remove(OAuthConsumerParameter.oauth_timestamp.toString())) <= (System.currentTimeMillis() / 1000));
    assertTrue(params.isEmpty());
  }

  /**
   * tests getting the signature base string.
   */
  public void testGetSignatureBaseString() throws Exception {
    HttpServletRequest request = createMock(HttpServletRequest.class);
    Map<String, String> oauthParams = new HashMap<String, String>();
    oauthParams.put("oauth_consumer_key", "dpf43f3p2l4k3l03");
    oauthParams.put("oauth_token", "nnch734d00sl2jdk");
    oauthParams.put("oauth_signature_method", "HMAC-SHA1");
    oauthParams.put("oauth_timestamp", "1191242096");
    oauthParams.put("oauth_nonce", "kllo9940pd9333jh");
    oauthParams.put("oauth_version", "1.0");
    oauthParams.put("file", "vacation.jpg");
    oauthParams.put("size", "original");

    CoreOAuthConsumerSupport support = new CoreOAuthConsumerSupport();

    replay(request);
    String baseString = support.getSignatureBaseString(oauthParams, new URL("http://photos.example.net/photos"), "geT");
    verify(request);
    assertEquals("GET&http%3A%2F%2Fphotos.example.net%2Fphotos&file%3Dvacation.jpg%26oauth_consumer_key%3Ddpf43f3p2l4k3l03%26oauth_nonce%3Dkllo9940pd9333jh%26oauth_signature_method%3DHMAC-SHA1%26oauth_timestamp%3D1191242096%26oauth_token%3Dnnch734d00sl2jdk%26oauth_version%3D1.0%26size%3Doriginal", baseString);
    reset(request);
  }
}
