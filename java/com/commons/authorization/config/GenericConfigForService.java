package com.commons.authorization.config;

import com.commons.authorization.security.JwtTokenAuthorizationOncePerRequestFilter;
import com.commons.authorization.security.JwtUnAuthorizedResponseAuthenticationEntryPoint;
import org.springframework.context.annotation.Bean;
import org.springframework.context.support.ResourceBundleMessageSource;
import org.springframework.stereotype.Component;

@Component
public class GenericConfigForService extends GenericConfigForAuth {

  @Bean
  public ResourceBundleMessageSource resourceBundleMessageSource() {
    return new ResourceBundleMessageSource();
  }

  @Bean
  public JwtUnAuthorizedResponseAuthenticationEntryPoint
      jwtUnAuthorizedResponseAuthenticationEntryPoint() {
    return new JwtUnAuthorizedResponseAuthenticationEntryPoint();
  }

  @Bean
  public JwtTokenAuthorizationOncePerRequestFilter jwtTokenAuthorizationOncePerRequestFilter() {
    return new JwtTokenAuthorizationOncePerRequestFilter();
  }

  @Bean
  public JWTWebSecurityConfigForServices jwtWebSecurityConfigForServices() {
    return new JWTWebSecurityConfigForServices();
  }

  @Bean
  public FeignClientInterceptor feignClientInterceptor() {
    return new FeignClientInterceptor();
  }
}
