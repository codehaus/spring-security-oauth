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
import org.springframework.beans.factory.support.RootBeanDefinition;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.PropertyValue;
import org.springframework.security.oauth.provider.*;
import org.springframework.security.oauth.provider.token.OAuthTokenLifecycleRegistryPostProcessor;
import org.springframework.security.oauth.provider.verifier.RandomValueInMemoryVerifierServices;
import org.springframework.security.oauth.provider.callback.InMemoryCallbackServices;
import org.springframework.security.config.BeanIds;
import org.springframework.security.web.util.UrlMatcher;
import org.springframework.security.web.util.AntUrlPathMatcher;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;
import org.apache.commons.logging.LogFactory;
import org.apache.commons.logging.Log;

import java.util.Map;
import java.util.List;

/**
 * Parser for the OAuth "provider" element.
 *
 * @author Ryan Heaton
 * @author Andrew McCall
 */
public class OAuthProviderBeanDefinitionParser implements BeanDefinitionParser {

  private static final Log LOG = LogFactory.getLog(OAuthProviderBeanDefinitionParser.class);

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

    String callbackUrlParam = element.getAttribute("callback-url-param");
    if (StringUtils.hasText(callbackUrlParam)) {
      authenticateTokenFilterBean.addPropertyValue("callbackParameterName", callbackUrlParam);
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

    BeanDefinition filterChainProxy = parserContext.getRegistry().getBeanDefinition(BeanIds.FILTER_CHAIN_PROXY);
    if (filterChainProxy != null) {
      PropertyValue propValue = filterChainProxy.getPropertyValues().getPropertyValue("filterChainMap");
      Map filterChainMap = propValue == null ? null : (Map) propValue.getValue();
      if (filterChainMap != null) {
        propValue = filterChainProxy.getPropertyValues().getPropertyValue("matcher");
        UrlMatcher matcher = propValue == null ? new AntUrlPathMatcher() : (UrlMatcher) propValue.getValue();
        List<BeanMetadataElement> filterChain = (List<BeanMetadataElement>) filterChainMap.get(matcher.getUniversalMatchPattern());

        if (filterChain != null) {
          int index = insertIndex(filterChain);
          parserContext.getRegistry().registerBeanDefinition("oauthRequestTokenFilter", requestTokenFilterBean.getBeanDefinition());
          filterChain.add(++index, new RuntimeBeanReference("oauthRequestTokenFilter"));
          parserContext.getRegistry().registerBeanDefinition("oauthAuthenticateTokenFilter", authenticateTokenFilterBean.getBeanDefinition());
          filterChain.add(++index, new RuntimeBeanReference("oauthAuthenticateTokenFilter"));
          parserContext.getRegistry().registerBeanDefinition("oauthAccessTokenFilter", accessTokenFilterBean.getBeanDefinition());
          filterChain.add(++index, new RuntimeBeanReference("oauthAccessTokenFilter"));
          parserContext.getRegistry().registerBeanDefinition("oauthProtectedResourceFilter", protectedResourceFilterBean.getBeanDefinition());
          filterChain.add(++index, new RuntimeBeanReference("oauthProtectedResourceFilter"));

          if (LOG.isDebugEnabled()) {
            StringBuffer buffer = new StringBuffer("FilterChain: ");
            for (int i = 0; i < filterChain.size(); i ++ ) {
              buffer.append("Index ");
              buffer.append(i);
              buffer.append(" - ");
              buffer.append(filterChain.get(i));
            }
          }
        }
        else {
          LOG.error("Unable to configure OAuth provider: no filter chain found for pattern " + matcher.getUniversalMatchPattern() + ".");
        }
      }
      else {
        LOG.error("Unable to configure OAuth provider: no filter chain map found in the configuration.");
      }
    }
    else {
      LOG.error("Unable to configure OAuth provider: no filter chain proxy found in the configuration.");
    }

    return null;
  }

  /**
   * Find the index into the filter chain from which to insert the OAuth provider filters.
   *
   * @param filterChain The filter chain.
   * @return The index.
   */
  private int insertIndex(List<BeanMetadataElement> filterChain) {
    if (LOG.isDebugEnabled()) {
      LOG.debug("Checking " + filterChain.size() + " filters to find insert index.");
    }

    int i;
    for (i = 0; i < filterChain.size(); i++) {
      RootBeanDefinition filter = (RootBeanDefinition) filterChain.get(i);
      String beanName = filter.getBeanClassName();
      if (beanName.equals(ExceptionTranslationFilter.class.getName())) {
         return i + 1;
      } 
    }
    return filterChain.size();
  }
}
