/*
 * Copyright 2008-2009 Web Cohesion
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

package org.springframework.security.oauth.config;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.config.BeanIds;
import org.springframework.security.config.ConfigUtilsBackdoor;
import org.springframework.security.oauth.provider.*;
import org.springframework.security.oauth.provider.callback.InMemoryCallbackServices;
import org.springframework.security.oauth.provider.token.OAuthTokenLifecycleRegistryPostProcessor;
import org.springframework.security.oauth.provider.verifier.RandomValueInMemoryVerifierServices;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

/**
 * Parser for the OAuth "provider" element.
 *
 * @author Ryan Heaton
 * @author Andrew McCall
 */
public class OAuthProviderBeanDefinitionParser implements BeanDefinitionParser {

  public BeanDefinition parse(Element element, ParserContext parserContext) {
    String consumerDetailsRef = element.getAttribute("consumer-details-service-ref");
    String tokenServicesRef = element.getAttribute("token-services-ref");

    BeanDefinitionBuilder requestTokenFilterBean = BeanDefinitionBuilder.rootBeanDefinition(UnauthenticatedRequestTokenProcessingFilter.class);
    if (StringUtils.hasText(consumerDetailsRef)) {
      requestTokenFilterBean.addPropertyReference("consumerDetailsService", consumerDetailsRef);
    }
    if (StringUtils.hasText(tokenServicesRef)) {
      requestTokenFilterBean.addPropertyReference("tokenServices", tokenServicesRef);
    }
    String requestTokenURL = element.getAttribute("request-token-url");
    if (StringUtils.hasText(requestTokenURL)) {
      requestTokenFilterBean.addPropertyValue("filterProcessesUrl", requestTokenURL);
    }

    BeanDefinitionBuilder authenticateTokenFilterBean = BeanDefinitionBuilder.rootBeanDefinition(UserAuthorizationProcessingFilter.class);

    authenticateTokenFilterBean.addPropertyReference("authenticationManager", BeanIds.AUTHENTICATION_MANAGER);
    if (StringUtils.hasText(tokenServicesRef)) {
      authenticateTokenFilterBean.addPropertyReference("tokenServices", tokenServicesRef);
    }

    String authenticateTokenURL = element.getAttribute("authenticate-token-url");
    if (StringUtils.hasText(authenticateTokenURL)) {
      authenticateTokenFilterBean.addPropertyValue("filterProcessesUrl", authenticateTokenURL);
    }

    String accessGrantedURL = element.getAttribute("access-granted-url");
    if (!StringUtils.hasText(accessGrantedURL)) {
      // create the simple URl handler and add it.
      accessGrantedURL = "/";
    }
    authenticateTokenFilterBean.addConstructorArgValue(accessGrantedURL);

    // create a AuthenticationFailureHandler
    BeanDefinitionBuilder simpleUrlAuthenticationFailureHandler = BeanDefinitionBuilder.rootBeanDefinition(SimpleUrlAuthenticationFailureHandler.class);
    String authenticationFailedURL = element.getAttribute("authentication-failed-url");
    if (StringUtils.hasText(authenticationFailedURL)) {
      simpleUrlAuthenticationFailureHandler.addConstructorArgValue (authenticationFailedURL);
    }
    else {
      simpleUrlAuthenticationFailureHandler.addConstructorArgValue ("/");
    }

    String tokenIdParam = element.getAttribute("token-id-param");
    if (StringUtils.hasText(tokenIdParam)) {
      authenticateTokenFilterBean.addPropertyValue("tokenIdParameterName", tokenIdParam);
    }

    BeanDefinitionBuilder accessTokenFilterBean = BeanDefinitionBuilder.rootBeanDefinition(AccessTokenProcessingFilter.class);

    if (StringUtils.hasText(consumerDetailsRef)) {
      accessTokenFilterBean.addPropertyReference("consumerDetailsService", consumerDetailsRef);
    }
    if (StringUtils.hasText(tokenServicesRef)) {
      accessTokenFilterBean.addPropertyReference("tokenServices", tokenServicesRef);
    }

    String accessTokenURL = element.getAttribute("access-token-url");
    if (StringUtils.hasText(accessTokenURL)) {
      accessTokenFilterBean.addPropertyValue("filterProcessesUrl", accessTokenURL);
    }

    BeanDefinitionBuilder protectedResourceFilterBean = BeanDefinitionBuilder.rootBeanDefinition(ProtectedResourceProcessingFilter.class);
    if (StringUtils.hasText(consumerDetailsRef)) {
      protectedResourceFilterBean.addPropertyReference("consumerDetailsService", consumerDetailsRef);
    }
    if (StringUtils.hasText(tokenServicesRef)) {
      protectedResourceFilterBean.addPropertyReference("tokenServices", tokenServicesRef);
    }

    String nonceServicesRef = element.getAttribute("nonce-services-ref");
    if (StringUtils.hasText(nonceServicesRef)) {
      requestTokenFilterBean.addPropertyReference("nonceServices", nonceServicesRef);
      accessTokenFilterBean.addPropertyReference("nonceServices", nonceServicesRef);
      protectedResourceFilterBean.addPropertyReference("nonceServices", nonceServicesRef);
    }

    String supportRef = element.getAttribute("support-ref");
    if (StringUtils.hasText(supportRef)) {
      requestTokenFilterBean.addPropertyReference("providerSupport", supportRef);
      accessTokenFilterBean.addPropertyReference("providerSupport", supportRef);
      protectedResourceFilterBean.addPropertyReference("providerSupport", supportRef);
    }

    String callbackServicesRef = element.getAttribute("callback-services-ref");
    if (!StringUtils.hasText(callbackServicesRef)) {
      BeanDefinitionBuilder callbackServices = BeanDefinitionBuilder.rootBeanDefinition(InMemoryCallbackServices.class);
      parserContext.getRegistry().registerBeanDefinition("oauthCallbackServices", callbackServices.getBeanDefinition());
      callbackServicesRef = "oauthCallbackServices";
    }
    requestTokenFilterBean.addPropertyReference("callbackServices", callbackServicesRef);
    authenticateTokenFilterBean.addPropertyReference("callbackServices", callbackServicesRef);

    BeanDefinitionBuilder successfulAuthenticationHandler = BeanDefinitionBuilder.rootBeanDefinition(UserAuthorizationSuccessfulAuthenticationHandler.class);
    successfulAuthenticationHandler.addConstructorArgValue(accessGrantedURL);
    successfulAuthenticationHandler.addPropertyReference("callbackServices", callbackServicesRef);

    String callbackUrlParam = element.getAttribute("callback-url-param");
    if (StringUtils.hasText(callbackUrlParam)) {
      successfulAuthenticationHandler.addPropertyValue("callbackParameterName", callbackUrlParam);
    }

    String require10a = element.getAttribute("require10a");
    if (StringUtils.hasText(require10a)) {
      requestTokenFilterBean.addPropertyValue("require10a", require10a);
      authenticateTokenFilterBean.addPropertyValue("require10a", require10a);
      accessTokenFilterBean.addPropertyValue("require10a", require10a);
      successfulAuthenticationHandler.addPropertyValue("require10a", require10a);
    }

    String verifierServicesRef = element.getAttribute("verifier-services-ref");
    if (!StringUtils.hasText(verifierServicesRef)) {
      BeanDefinitionBuilder verifierServices = BeanDefinitionBuilder.rootBeanDefinition(RandomValueInMemoryVerifierServices.class);
      parserContext.getRegistry().registerBeanDefinition("oauthVerifierServices", verifierServices.getBeanDefinition());
      verifierServicesRef = "oauthVerifierServices";
    }
    successfulAuthenticationHandler.addPropertyReference("verifierServices", verifierServicesRef);
    accessTokenFilterBean.addPropertyReference("verifierServices", verifierServicesRef);

    // register the successfulAuthenticationHandler with the UserAuthorizationFilter
    String oauthSuccessfulAuthenticationHandlerRef = "oauthSuccessfulAuthenticationHandler";
    parserContext.getRegistry().registerBeanDefinition(oauthSuccessfulAuthenticationHandlerRef, successfulAuthenticationHandler.getBeanDefinition());
    authenticateTokenFilterBean.addPropertyReference("authenticationSuccessHandler", oauthSuccessfulAuthenticationHandlerRef);

    parserContext.getRegistry().registerBeanDefinition("_oauthTokenRegistryPostProcessor",
      BeanDefinitionBuilder.rootBeanDefinition(OAuthTokenLifecycleRegistryPostProcessor.class).getBeanDefinition());

    parserContext.getRegistry().registerBeanDefinition("oauthRequestTokenFilter", requestTokenFilterBean.getBeanDefinition());
    ConfigUtilsBackdoor.addHttpFilter(parserContext, new RuntimeBeanReference("oauthRequestTokenFilter"));
    parserContext.getRegistry().registerBeanDefinition("oauthAuthenticateTokenFilter", authenticateTokenFilterBean.getBeanDefinition());
    ConfigUtilsBackdoor.addHttpFilter(parserContext, new RuntimeBeanReference("oauthAuthenticateTokenFilter"));
    parserContext.getRegistry().registerBeanDefinition("oauthAccessTokenFilter", accessTokenFilterBean.getBeanDefinition());
    ConfigUtilsBackdoor.addHttpFilter(parserContext, new RuntimeBeanReference("oauthAccessTokenFilter"));
    parserContext.getRegistry().registerBeanDefinition("oauthProtectedResourceFilter", protectedResourceFilterBean.getBeanDefinition());
    ConfigUtilsBackdoor.addHttpFilter(parserContext, new RuntimeBeanReference("oauthProtectedResourceFilter"));

    return null;
  }

}
