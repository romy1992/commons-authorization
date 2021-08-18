package com.commons.authorization.config;

import com.commons.authorization.security.JwtTokenAuthorizationOncePerRequestFilter;
import feign.RequestInterceptor;
import feign.RequestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

@Component
public class FeignClientInterceptor implements RequestInterceptor {

  private static final String AUTHORIZATION_HEADER = "Authorization";

  @Autowired
  private JwtTokenAuthorizationOncePerRequestFilter jwtTokenAuthorizationOncePerRequestFilter;

  @Override
  public void apply(RequestTemplate requestTemplate) {
    requestTemplate.header(
        AUTHORIZATION_HEADER, jwtTokenAuthorizationOncePerRequestFilter.getTokenAuth());
  }
}
