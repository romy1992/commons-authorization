package com.commons.authorization.config;

import com.commons.authorization.security.CustomLocalDetailsService;
import com.commons.authorization.security.JwtTokenUtil;
import com.commons.authorization.security.model.JwtConfig;
import com.commons.authorization.security.model.ModelConfig;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

@Component
public class GenericConfigForAuth {

  @Bean
  public CustomLocalDetailsService customUserDetailsService() {
    return new CustomLocalDetailsService();
  }

  @Bean
  public ModelConfig userConfig() {
    return new ModelConfig();
  }

  @Bean
  public JwtConfig jwtConfig() {
    return new JwtConfig();
  }

  @Bean
  public JwtTokenUtil jwtTokenUtil() {
    return new JwtTokenUtil();
  }

  @Bean
  public RestTemplate restTemplate() {
    return new RestTemplate();
  }

}
