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

package org.springframework.security.oauth2.config;

import org.springframework.beans.BeanMetadataElement;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.beans.factory.config.RuntimeBeanReference;
import org.springframework.beans.factory.support.BeanDefinitionBuilder;
import org.springframework.beans.factory.support.ManagedList;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.ParserContext;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.BeanIds;
import org.springframework.security.oauth2.provider.*;
import org.springframework.security.oauth2.provider.token.InMemoryOAuth2ProviderTokenServices;
import org.springframework.security.oauth2.provider.usernamepassword.UsernamePasswordOAuth2AuthenticationProvider;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.util.StringUtils;
import org.w3c.dom.Element;

import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Parser for the OAuth "provider" element.
 *
 * @author Ryan Heaton
 * @author Andrew McCall
 */
public class OAuth2ProviderBeanDefinitionParser implements BeanDefinitionParser {

  public static String OAUTH2_AUTHENTICATION_MANAGER = "OAuth2" + BeanIds.AUTHENTICATION_MANAGER;

  public BeanDefinition parse(Element element, ParserContext parserContext) {
    String clientDetailsRef = element.getAttribute("client-details-service-ref");
    String tokenServicesRef = element.getAttribute("token-services-ref");
    String authUrl = element.getAttribute("authorization-url");
    String defaultFlow = element.getAttribute("default-flow");
    String authSuccessHandlerRef = element.getAttribute("authorization-success-handler-ref");
    String serializerRef = element.getAttribute("serialization-service-ref");
    String valveRef = element.getAttribute("valve-ref");

    if (!StringUtils.hasText(tokenServicesRef)) {
      tokenServicesRef = "oauth2TokenServices";
      BeanDefinitionBuilder tokenServices = BeanDefinitionBuilder.rootBeanDefinition(InMemoryOAuth2ProviderTokenServices.class);
      parserContext.getRegistry().registerBeanDefinition(tokenServicesRef, tokenServices.getBeanDefinition());
    }

    if (!StringUtils.hasText(authSuccessHandlerRef)) {
      authSuccessHandlerRef = "oauth2AuthorizationSuccessHandler";
      BeanDefinitionBuilder successHandler = BeanDefinitionBuilder.rootBeanDefinition(OAuth2AuthorizationSuccessHandler.class);
      if (StringUtils.hasText(serializerRef)) {
        successHandler.addPropertyReference("serializationService", serializerRef);
      }
      if (StringUtils.hasText(tokenServicesRef)) {
        successHandler.addPropertyReference("tokenServices", tokenServicesRef);
      }
      parserContext.getRegistry().registerBeanDefinition(authSuccessHandlerRef, successHandler.getBeanDefinition());
    }

    BeanDefinitionBuilder authFilterBean = BeanDefinitionBuilder.rootBeanDefinition(OAuth2AuthorizationFilter.class);
    if (StringUtils.hasText(authUrl)) {
      authFilterBean.addPropertyValue("filterProcessesUrl", authUrl);
    }
    if (StringUtils.hasText(authSuccessHandlerRef)) {
      authFilterBean.addPropertyReference("authenticationSuccessHandler", authSuccessHandlerRef);
    }
    if (StringUtils.hasText(defaultFlow)) {
      authFilterBean.addPropertyValue("defaultFlowType", defaultFlow);
    }
    if (StringUtils.hasText(valveRef)) {
      authFilterBean.addPropertyReference("valve", valveRef);
    }
    authFilterBean.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);

    //instantiate the oauth provider manager...
    BeanDefinitionBuilder oauthProviderManagerBean = BeanDefinitionBuilder.rootBeanDefinition(ProviderManager.class);
    oauthProviderManagerBean.addPropertyReference("parent", BeanIds.AUTHENTICATION_MANAGER);

    BeanDefinitionBuilder usernamePasswordProvider = BeanDefinitionBuilder.rootBeanDefinition(UsernamePasswordOAuth2AuthenticationProvider.class);
    usernamePasswordProvider.addPropertyReference("authenticationManager", OAUTH2_AUTHENTICATION_MANAGER);

    BeanDefinitionBuilder clientAuthProvider = BeanDefinitionBuilder.rootBeanDefinition(ClientAuthenticationProvider.class);
    if (StringUtils.hasText(clientDetailsRef)) {
      clientAuthProvider.addPropertyReference("clientDetailsService", clientDetailsRef);
    }

    BeanDefinitionBuilder exceptionHandler = BeanDefinitionBuilder.rootBeanDefinition(OAuth2ExceptionHandlerFilter.class);
    if (StringUtils.hasText(serializerRef)) {
      exceptionHandler.addPropertyReference("serializationService", serializerRef);
    }

    List<BeanMetadataElement> providers = new ManagedList<BeanMetadataElement>();
    providers.add(usernamePasswordProvider.getBeanDefinition());
    providers.add(clientAuthProvider.getBeanDefinition());
    oauthProviderManagerBean.addPropertyValue("providers", providers);

    BeanDefinitionBuilder protectedResourceFilterBean = BeanDefinitionBuilder.rootBeanDefinition(OAuth2ProtectedResourceFilter.class);
    if (StringUtils.hasText(tokenServicesRef)) {
      protectedResourceFilterBean.addPropertyReference("tokenServices", tokenServicesRef);
    }

    BeanDefinition filterChainProxy = parserContext.getRegistry().getBeanDefinition(BeanIds.FILTER_CHAIN_PROXY);
    Map filterChainMap = (Map) filterChainProxy.getPropertyValues().getPropertyValue("filterChainMap").getValue();
    List<BeanMetadataElement> filterChain = findFilterChain(filterChainMap);

    if (filterChain == null) {
      throw new IllegalStateException("Unable to find the filter chain for the universal pattern matcher where the oauth filters are to be inserted.");
    }

    int index = insertIndex(filterChain);
    parserContext.getRegistry().registerBeanDefinition("oauth2ExceptionHandlerFilter", exceptionHandler.getBeanDefinition());
    filterChain.add(index++, new RuntimeBeanReference("oauth2ExceptionHandlerFilter"));
    parserContext.getRegistry().registerBeanDefinition("oauth2AuthorizationFilter", authFilterBean.getBeanDefinition());
    filterChain.add(index++, new RuntimeBeanReference("oauth2AuthorizationFilter"));
    parserContext.getRegistry().registerBeanDefinition("oauth2ProtectedResourceFilter", protectedResourceFilterBean.getBeanDefinition());
    filterChain.add(index++, new RuntimeBeanReference("oauth2ProtectedResourceFilter"));

    parserContext.getRegistry().registerBeanDefinition(OAUTH2_AUTHENTICATION_MANAGER, oauthProviderManagerBean.getBeanDefinition());
    parserContext.getRegistry().registerBeanDefinition("oauth2UsernamePasswordProvider", usernamePasswordProvider.getBeanDefinition());
    parserContext.getRegistry().registerBeanDefinition("oauth2ClientProvider", clientAuthProvider.getBeanDefinition());
    return null;
  }

  protected List<BeanMetadataElement> findFilterChain(Map filterChainMap) {
    //the filter chain we want is the last one in the sorted map.
    Iterator valuesIt = filterChainMap.values().iterator();
    while (valuesIt.hasNext()) {
      List<BeanMetadataElement> filterChain = (List<BeanMetadataElement>) valuesIt.next();
      if (!valuesIt.hasNext()) {
        return filterChain;
      }
    }

    return null;
  }

  /**
   * Attempts to find the place in the filter chain to insert the spring security oauth filters. Currently,
   * these filters are inserted after the ExceptionTranslationFilter.
   *
   * @param filterChain The filter chain configuration.
   * @return The insert index.
   */
  private int insertIndex(List<BeanMetadataElement> filterChain) {
    int i;
    for (i = 0; i < filterChain.size(); i++) {
      BeanMetadataElement filter = filterChain.get(i);
      if (filter instanceof BeanDefinition) {
        String beanName = ((BeanDefinition) filter).getBeanClassName();
        if (beanName.equals(ExceptionTranslationFilter.class.getName())) {
           return i + 1;
        }
      }
    }
    return filterChain.size();
  }
}